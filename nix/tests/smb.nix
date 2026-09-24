{ pkgs, self, system }:
let
  vaultlink = self.packages.${system}.vaultlink;
  configFile = pkgs.writeText "vaultlink-smb-test.toml" ''
    [server]
    mode = "development"
    listen_address = "127.0.0.1:8080"
    public_base_url = "http://localhost:8080"

    [storage]
    root_mount_path = "/mnt/storage"
    data_directory = "/var/lib/vaultlink"
    internal_directory = "/mnt/storage/.vaultlink-internal"
    require_mount = true
    external_writers = true
    allow_external_writer_replace = false
    expected_filesystem_type = "cifs"
    expected_mount_source = "//server/vaultlink"
  '';
in pkgs.testers.runNixOSTest {
  name = "vaultlink-smb-${system}";
  nodes = {
    server = { pkgs, ... }: {
      environment.systemPackages = with pkgs; [ samba ];
      networking.firewall.allowedTCPPorts = [ 445 ];
      services.samba = {
        enable = true;
        settings = {
          global = {
            "server min protocol" = "SMB3_11";
            "server smb encrypt" = "required";
          };
          vaultlink = {
            path = "/srv/vaultlink";
            "read only" = "no";
            "valid users" = "vaultlink";
          };
        };
      };
      users.groups.vaultlink = { };
      users.users.vaultlink = {
        isSystemUser = true;
        group = "vaultlink";
      };
    };
    client = { pkgs, ... }: {
      imports = [ self.nixosModules.default ];
      environment.systemPackages = with pkgs; [ curl cifs-utils python3 sqlite util-linux ];
      services.vaultlink = {
        enable = true;
        package = vaultlink;
        storageMountPath = "/mnt/storage";
      };
    };
  };
  testScript = ''
    server.start()
    client.start()
    server.wait_for_unit("samba-smbd.service")
    client.wait_for_unit("multi-user.target")
    client.succeed("runuser -u vaultlink -- env VAULTLINK_BIN=${vaultlink}/bin/vaultlink VAULTLINK_SMOKE_DIR=/var/lib/vaultlink/setup/api-smoke bash ${../../deploy/docker/api-smoke.sh}")
    client.succeed("test -f /var/lib/vaultlink/setup/api-smoke/data/data.sqlite")
    server.succeed("install -d -o vaultlink -g vaultlink -m 0700 /srv/vaultlink /srv/vaultlink/.vaultlink-internal /srv/vaultlink/.vaultlink-internal/uploads /srv/vaultlink/.vaultlink-internal/tombstones")
    server.succeed("printf 'test-password\\ntest-password\\n' | smbpasswd -a -s vaultlink >/dev/null")
    client.succeed("mkdir -p /mnt/storage")
    client.succeed("mount -t cifs //server/vaultlink /mnt/storage -o username=vaultlink,password=test-password,vers=3.1.1,sec=ntlmsspi,seal,cache=strict,serverino,nosuid,nodev,noexec,uid=vaultlink,gid=vaultlink,file_mode=0600,dir_mode=0700")
    client.succeed("install -o root -g vaultlink -m 0640 ${configFile} /etc/vaultlink/config.toml")
    client.succeed("systemctl reset-failed vaultlink.service; systemctl restart vaultlink.service")
    client.wait_for_unit("vaultlink.service")
    client.wait_until_succeeds("curl --fail --silent http://127.0.0.1:8080/api/v2/health/ready | grep -q '\"ok\":true'")
    client.succeed("test \"$(sqlite3 /var/lib/vaultlink/data.sqlite 'PRAGMA integrity_check')\" = ok")
    client.succeed("install -d -o vaultlink -g vaultlink -m 0700 /var/lib/vaultlink/second")
    client.succeed("sed -e 's/127.0.0.1:8080/127.0.0.1:8081/g' -e 's@data_directory = \"/var/lib/vaultlink\"@data_directory = \"/var/lib/vaultlink/second\"@' /etc/vaultlink/config.toml > /etc/vaultlink/second.toml; chgrp vaultlink /etc/vaultlink/second.toml; chmod 0640 /etc/vaultlink/second.toml")
    client.succeed("grep -Fq 'data_directory = \"/var/lib/vaultlink/second\"' /etc/vaultlink/second.toml")
    client.fail("runuser -u vaultlink -- ${vaultlink}/bin/vaultlink --config /etc/vaultlink/second.toml > /tmp/vaultlink-second.log 2>&1")
    client.succeed("grep -q 'Error: Contended.*\\.vaultlink-instance.lock' /tmp/vaultlink-second.log || { cat /tmp/vaultlink-second.log; exit 1; }")
    client.succeed("systemctl restart vaultlink.service")
    client.wait_until_succeeds("curl --fail --silent http://127.0.0.1:8080/api/v2/health/ready | grep -q '\"ok\":true'")
    client.succeed("systemctl stop vaultlink.service")
    client.succeed("runuser -u vaultlink -- mkdir -m 0700 /mnt/storage/shared /mnt/storage/data")
    client.succeed("sed -i 's@root_mount_path = \"/mnt/storage\"@root_mount_path = \"/mnt/storage/shared\"@' /etc/vaultlink/config.toml")
    client.succeed("grep -Fq 'root_mount_path = \"/mnt/storage/shared\"' /etc/vaultlink/config.toml")
    client.succeed("sed -i 's@data_directory = \"/var/lib/vaultlink\"@data_directory = \"/mnt/storage/data\"@' /etc/vaultlink/config.toml")
    client.fail("runuser -u vaultlink -- ${vaultlink}/bin/vaultlink --config /etc/vaultlink/config.toml > /tmp/vaultlink-remote-sqlite.log 2>&1")
    client.succeed("grep -q 'SQLite.*separate filesystem\|SQLite/WAL requires local' /tmp/vaultlink-remote-sqlite.log || { cat /tmp/vaultlink-remote-sqlite.log; exit 1; }")
    client.succeed("sed -i 's@data_directory = \"/mnt/storage/data\"@data_directory = \"/var/lib/vaultlink\"@' /etc/vaultlink/config.toml")
    client.succeed("umount /mnt/storage")
    client.fail("runuser -u vaultlink -- ${vaultlink}/bin/vaultlink --config /etc/vaultlink/config.toml")
  '';
}
