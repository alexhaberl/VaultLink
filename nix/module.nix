{ self }:
{ config, lib, pkgs, ... }:
let
  cfg = config.services.vaultlink;
  validAbsolutePath = path:
    lib.hasPrefix "/" path
    && lib.all (segment:
      segment != "" && segment != "." && segment != ".."
      && builtins.match "^[^[:space:]]+$" segment != null
    ) (lib.tail (lib.splitString "/" path));
in {
  options.services.vaultlink = {
    enable = lib.mkEnableOption "VaultLink file sharing";
    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.vaultlink;
      description = "The VaultLink release built by this flake.";
    };
    configFile = lib.mkOption {
      type = lib.types.str;
      default = "/etc/vaultlink/config.toml";
      description = "Private, root-managed VaultLink TOML file outside the Nix store.";
    };
    storageMountPath = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "The mounted storage filesystem containing VaultLink's shared root and private lock domain.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = config.system.nixos.release == "26.05";
        message = "VaultLink currently supports only NixOS 26.05.";
      }
      {
        assertion = cfg.storageMountPath != null
          && validAbsolutePath cfg.storageMountPath;
        message = "services.vaultlink.storageMountPath must be an absolute mount path.";
      }
      {
        assertion = validAbsolutePath cfg.configFile
          && cfg.configFile != "/nix/store"
          && !(lib.hasPrefix "/nix/store/" cfg.configFile);
        message = "services.vaultlink.configFile must be an absolute path outside the Nix store.";
      }
    ];

    users.groups.vaultlink = { };
    users.groups.vaultlink-proxy = { };
    environment.systemPackages = [ cfg.package ];
    users.users.vaultlink = {
      isSystemUser = true;
      group = "vaultlink";
      home = "/var/lib/vaultlink";
    };

    systemd.tmpfiles.rules = [
      "d /etc/vaultlink 0750 root vaultlink -"
      "d /var/lib/vaultlink 0750 vaultlink vaultlink -"
      "d /var/lib/vaultlink/setup 0700 vaultlink vaultlink -"
      "d /var/log/vaultlink 0750 vaultlink vaultlink -"
    ];

    systemd.services.vaultlink = {
      description = "VaultLink secure file sharing";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" "local-fs.target" "remote-fs.target" ];
      unitConfig = {
        ConditionPathExists = cfg.configFile;
        RequiresMountsFor = cfg.storageMountPath;
        StartLimitIntervalSec = "1h";
        StartLimitBurst = 3;
      };
      serviceConfig = {
        Type = "simple";
        User = "vaultlink";
        Group = "vaultlink-proxy";
        SupplementaryGroups = [ "vaultlink" ];
        RuntimeDirectory = "vaultlink-proxy";
        RuntimeDirectoryMode = "0750";
        Environment = [ "MALLOC_ARENA_MAX=4" "VAULTLINK_INSTALL_METHOD=nixos" ];
        ExecStart = "${cfg.package}/bin/vaultlink --config ${lib.escapeShellArg cfg.configFile}";
        ExecReload = "${pkgs.coreutils}/bin/kill -HUP $MAINPID";
        Restart = "on-failure";
        RestartSec = "5s";
        TimeoutStopSec = "45s";
        UMask = "0077";
        LimitNOFILE = 4096;
        LimitCORE = 0;
        TasksMax = 512;
        NoNewPrivileges = true;
        SystemCallArchitectures = "native";
        PrivateTmp = true;
        PrivateDevices = true;
        PrivateIPC = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectHostname = true;
        ProtectProc = "invisible";
        ProcSubset = "pid";
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        RestrictRealtime = true;
        RestrictNamespaces = true;
        RemoveIPC = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallFilter = [ "@system-service" "openat2" "renameat2" "statx" ];
        SystemCallErrorNumber = "EPERM";
        CapabilityBoundingSet = "";
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
        ReadWritePaths = [ "/var/lib/vaultlink" "/var/log/vaultlink" cfg.storageMountPath ];
        ReadOnlyPaths = [ (builtins.dirOf cfg.configFile) ];
      };
    };
  };
}
