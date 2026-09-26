{ pkgs, self, system, oldPackage }:
let
  vaultlink = self.packages.${system}.vaultlink;
  configFile = pkgs.writeText "vaultlink-upgrade-test.toml" ''
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
  name = "vaultlink-upgrade-${system}";
  requiredFeatures.kvm = system != "aarch64-linux";
  nodes.machine = { pkgs, lib, ... }: {
    imports = [ self.nixosModules.default ];
    boot.loader.grub.enable = lib.mkForce false;
    virtualisation.emptyDiskImages = [ 1024 ];
    environment.systemPackages = with pkgs; [ curl e2fsprogs sqlite util-linux ];
    services.vaultlink = {
      enable = true;
      package = oldPackage;
      storageMountPath = "/mnt/storage";
    };
    specialisation.new.configuration.services.vaultlink.package = lib.mkForce vaultlink;
  };
  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("mkfs.ext4 -q /dev/vdb")
    machine.succeed("mkdir -p /mnt/storage && mount -t ext4 /dev/vdb /mnt/storage")
    machine.succeed("install -d -o vaultlink -g vaultlink -m 0700 /mnt/storage/shared /mnt/storage/.vaultlink-internal /mnt/storage/.vaultlink-internal/uploads /mnt/storage/.vaultlink-internal/tombstones")
    machine.succeed("printf 'persistent upgrade payload\n' > /mnt/storage/shared/payload.txt; chown vaultlink:vaultlink /mnt/storage/shared/payload.txt")
    machine.succeed("install -o root -g vaultlink -m 0640 ${configFile} /etc/vaultlink/config.toml")
    machine.succeed("systemctl reset-failed vaultlink.service; systemctl restart vaultlink.service")
    machine.wait_until_succeeds("curl --fail --silent http://127.0.0.1:8080/api/v2/health/ready | grep -q '0.7.1'")
    machine.succeed("test -s /var/lib/vaultlink/data.sqlite && test -s /var/lib/vaultlink/secrets.keyring")
    old_system = machine.succeed("readlink -f /run/current-system").strip()
    machine.succeed("systemctl stop vaultlink.service")
    machine.succeed("test \"$(sqlite3 /var/lib/vaultlink/data.sqlite 'PRAGMA integrity_check')\" = ok")
    machine.succeed("sqlite3 /var/lib/vaultlink/data.sqlite 'PRAGMA wal_checkpoint(TRUNCATE)' >/dev/null")
    machine.succeed("install -d -o root -g root -m 0700 /var/backups/vaultlink-upgrade-test")
    machine.succeed("cp -L ${oldPackage}/bin/vaultlink /var/backups/vaultlink-upgrade-test/vaultlink; cp -a /etc/vaultlink/config.toml /var/lib/vaultlink/data.sqlite /var/lib/vaultlink/secrets.keyring /var/backups/vaultlink-upgrade-test/")
    machine.succeed("cd /var/backups/vaultlink-upgrade-test && sha256sum vaultlink config.toml data.sqlite secrets.keyring > SHA256SUMS")
    machine.succeed("/run/current-system/specialisation/new/bin/switch-to-configuration switch")
    machine.wait_until_succeeds("curl --fail --silent http://127.0.0.1:8080/api/v2/health/ready | grep -q '${vaultlink.version}'")
    machine.succeed("test \"$(sqlite3 /var/lib/vaultlink/data.sqlite 'PRAGMA integrity_check')\" = ok")
    machine.succeed("systemctl stop vaultlink.service; systemctl mask --runtime vaultlink.service")
    machine.succeed("mv /etc/vaultlink/config.toml /etc/vaultlink/config.toml.failed-generation")
    machine.succeed(f"{old_system}/bin/switch-to-configuration switch")
    machine.succeed("test ! -e /etc/vaultlink/config.toml && ! systemctl is-active --quiet vaultlink.service")
    machine.succeed("cd /var/backups/vaultlink-upgrade-test && sha256sum -c SHA256SUMS")
    machine.succeed("rm -f /var/lib/vaultlink/data.sqlite-wal /var/lib/vaultlink/data.sqlite-shm")
    machine.succeed("cp -a /var/backups/vaultlink-upgrade-test/data.sqlite /var/backups/vaultlink-upgrade-test/secrets.keyring /var/lib/vaultlink/; cp -a /var/backups/vaultlink-upgrade-test/config.toml /etc/vaultlink/config.toml")
    machine.succeed("cmp /var/lib/vaultlink/data.sqlite /var/backups/vaultlink-upgrade-test/data.sqlite; cmp /var/lib/vaultlink/secrets.keyring /var/backups/vaultlink-upgrade-test/secrets.keyring")
    machine.succeed("test \"$(sqlite3 /var/lib/vaultlink/data.sqlite 'PRAGMA integrity_check')\" = ok")
    machine.succeed("systemctl unmask --runtime vaultlink.service; systemctl reset-failed vaultlink.service; systemctl start vaultlink.service")
    machine.wait_until_succeeds("curl --fail --silent http://127.0.0.1:8080/api/v2/health/ready | grep -q '0.7.1'")
    machine.succeed("test \"$(sha256sum /proc/$(systemctl show -p MainPID --value vaultlink.service)/exe | cut -d' ' -f1)\" = \"$(sha256sum /var/backups/vaultlink-upgrade-test/vaultlink | cut -d' ' -f1)\"")
    machine.succeed("test \"$(sha256sum /mnt/storage/shared/payload.txt | cut -d' ' -f1)\" = \"$(printf 'persistent upgrade payload\n' | sha256sum | cut -d' ' -f1)\"")
  '';
}
