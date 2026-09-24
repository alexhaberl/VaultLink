{ pkgs, self, system }:
let
  vaultlink = self.packages.${system}.vaultlink;
  configFile = pkgs.writeText "vaultlink-local-test.toml" ''
    [server]
    mode = "development"
    listen_address = "127.0.0.1:8080"
    public_base_url = "http://localhost:8080"

    [storage]
    root_mount_path = "/mnt/storage/shared"
    data_directory = "/var/lib/vaultlink"
    internal_directory = "/mnt/storage/.vaultlink-internal"
    require_mount = true
    external_writers = false
    allow_external_writer_replace = false
    expected_filesystem_type = "ext4"
    expected_mount_source = "/dev/vdb"
  '';
in pkgs.testers.runNixOSTest {
  name = "vaultlink-local-${system}";
  nodes.machine = { pkgs, ... }: {
    imports = [ self.nixosModules.default ];
    virtualisation.emptyDiskImages = [ 1024 ];
    environment.systemPackages = with pkgs; [ curl e2fsprogs python3 sqlite util-linux ];
    services.vaultlink = {
      enable = true;
      package = vaultlink;
      storageMountPath = "/mnt/storage";
    };
  };
  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("runuser -u vaultlink -- env VAULTLINK_BIN=${vaultlink}/bin/vaultlink VAULTLINK_SMOKE_DIR=/var/lib/vaultlink/setup/api-smoke bash ${../../deploy/docker/api-smoke.sh}")
    machine.succeed("test -f /var/lib/vaultlink/setup/api-smoke/data/data.sqlite")
    machine.succeed("test -b /dev/vdb")
    machine.succeed("mkfs.ext4 -q /dev/vdb")
    machine.succeed("mkdir -p /mnt/storage && mount -t ext4 /dev/vdb /mnt/storage")
    machine.succeed("test \"$(findmnt -n -o SOURCE /mnt/storage)\" = /dev/vdb")
    machine.succeed("install -d -o vaultlink -g vaultlink -m 0700 /mnt/storage/shared")
    machine.succeed("install -d -o vaultlink -g vaultlink -m 0700 /mnt/storage/.vaultlink-internal /mnt/storage/.vaultlink-internal/uploads /mnt/storage/.vaultlink-internal/tombstones")
    machine.succeed("install -o root -g vaultlink -m 0640 ${configFile} /etc/vaultlink/config.toml")
    machine.succeed("systemctl reset-failed vaultlink.service; systemctl restart vaultlink.service")
    machine.wait_for_unit("vaultlink.service")
    machine.wait_until_succeeds("curl --fail --silent http://127.0.0.1:8080/api/v2/health/ready | grep -q '\"ok\":true'")
    machine.succeed("test \"$(systemctl show -p User --value vaultlink.service)\" = vaultlink")
    machine.succeed("test \"$(sqlite3 /var/lib/vaultlink/data.sqlite 'PRAGMA integrity_check')\" = ok")
    machine.fail("runuser -u vaultlink -- ${vaultlink}/bin/vaultlink --config /etc/vaultlink/config.toml")
    machine.succeed("systemctl restart vaultlink.service")
    machine.wait_until_succeeds("curl --fail --silent http://127.0.0.1:8080/api/v2/health/ready | grep -q '\"ok\":true'")
    machine.succeed("runuser -u vaultlink -- ${vaultlink}/bin/vaultlink --version")
    machine.succeed("test ! -e /usr/share/vaultlink/install-method.env && test ! -e /usr/sbin/vaultlink-update")
    machine.succeed("systemctl stop vaultlink.service")
    machine.succeed("chmod 0777 /mnt/storage/shared")
    machine.fail("runuser -u vaultlink -- ${vaultlink}/bin/vaultlink --config /etc/vaultlink/config.toml")
    machine.succeed("chmod 0700 /mnt/storage/shared")
    machine.succeed("sed -i 's@/dev/vdb@/dev/incorrect@' /etc/vaultlink/config.toml")
    machine.fail("runuser -u vaultlink -- ${vaultlink}/bin/vaultlink --config /etc/vaultlink/config.toml")
    machine.succeed("sed -i 's@/dev/incorrect@/dev/vdb@' /etc/vaultlink/config.toml")
    machine.succeed("umount /mnt/storage")
    machine.fail("runuser -u vaultlink -- ${vaultlink}/bin/vaultlink --config /etc/vaultlink/config.toml")
  '';
}
