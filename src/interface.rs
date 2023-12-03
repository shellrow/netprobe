use xenet::net::interface::Interface;

pub(crate) fn get_interface_by_index(index: u32) -> Option<Interface> {
    for iface in xenet::net::interface::get_interfaces() {
        if iface.index == index {
            return Some(iface);
        }
    }
    return None;
}
