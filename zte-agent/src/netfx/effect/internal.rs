use crate::net_tools as net;

type Handler = fn(&[String]) -> Result<(), String>;
type Check = fn(&[String]) -> Result<bool, String>;

pub(crate) struct InternalHandler {
    pub name: &'static str,
    pub apply: Handler,
    pub check: Option<Check>,
}

pub(crate) const HANDLERS: &[InternalHandler] = &[
    InternalHandler { name: "@u60-relay-channel", apply: crate::wifi_relay::hotspot::switch, check: None },
    InternalHandler { name: "@u60-relay-ipv6-dad", apply: crate::wifi_relay::ipv6::wait_addresses, check: None },
    InternalHandler { name: "@u60-relay-ra", apply: crate::wifi_relay::ipv6::ra_command, check: None },
    InternalHandler { name: "@u60-relay-dns", apply: crate::wifi_relay::dns::command, check: None },
    InternalHandler { name: "@u60-relay-portal", apply: crate::wifi_relay::portal::command, check: None },
    InternalHandler { name: "@u60-sysctl", apply: net::sysctl_command, check: Some(sysctl_present) },
    InternalHandler { name: "@u60-mihomo-nft", apply: crate::mihomo::nft_command, check: None },
    InternalHandler { name: "@u60-relay-steer", apply: crate::wifi_relay::steering::command, check: Some(steering_present) },
    InternalHandler { name: "@u60-relay-power-save", apply: crate::wifi_relay::power_save::command, check: Some(crate::wifi_relay::power_save::present) },
    InternalHandler { name: "@u60-relay-nft", apply: crate::wifi_relay::uplink::command, check: None },
    InternalHandler { name: "@u60-relay-roam", apply: roam, check: None },
    InternalHandler { name: "@u60-relay-detach", apply: detach, check: None },
];

pub(crate) fn handler(name: &str) -> Option<&'static InternalHandler> {
    HANDLERS.iter().find(|handler| handler.name == name)
}

fn roam(args: &[String]) -> Result<(), String> {
    match args {
        [mode] if matches!(mode.as_str(), "0" | "1") => crate::wifi_relay::restore_roam(mode),
        _ => Err("Invalid relay recovery mode".into()),
    }
}

fn detach(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        crate::wifi_relay::detach_station()
    } else {
        Err("Invalid relay disconnect recovery".into())
    }
}

fn steering_present(args: &[String]) -> Result<bool, String> {
    Ok(crate::wifi_relay::steering::present(args))
}

fn sysctl_present(args: &[String]) -> Result<bool, String> {
    match args {
        [key, value] => net::sysctl_read(key).map(|current| current == *value),
        _ => Err("Invalid kernel setting".into()),
    }
}
