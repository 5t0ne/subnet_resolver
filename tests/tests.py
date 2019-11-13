import ipaddress
from subnet_resolver import check_if_ip_in_stored_sub_nets, \
    get_subnet_for_ipv4, \
    load_stored_net_masks


def test_check_existing_sub_nets():
    test_nets = set()
    test_nets.add(('54.76.0.0', '15'))
    test_ip = '54.77.121.183'
    result = check_if_ip_in_stored_sub_nets(test_ip, test_nets)
    assert result is True


def test_get_subnet_for_ip():
    test_ip = '54.77.121.183'
    expected_net_mask = '54.76.0.0'
    expected_bit_mask = '15'
    net_mask, bit_mask = get_subnet_for_ipv4(test_ip)
    assert net_mask == expected_net_mask
    assert bit_mask == expected_bit_mask


def test_load_stored_net_masks():
    TEST_CONFIG_PATH = './resources/test_net_masks.conf'
    test_config = load_stored_net_masks(TEST_CONFIG_PATH)
    assert ('52.208.0.0','13') in test_config
