import os
import shutil
import unittest
from functools import partial

from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet

from config import *
from topos.single_switch import SingleSwitchTopo
from utils import file_hashes, is_port_open, wait_for


class TestServeFile(unittest.TestCase):
    def setUp(self):
        # os.makedirs('tests/data/tmp-data')

        setLogLevel(config.MININET_LOG_LEVEL)
        self.topo = SingleSwitchTopo(n=2)
        self.net = Mininet(topo=self.topo, host=CPULimitedHost, link=TCLink)
        self.net.start()

    def test_download_small(self):
        server_file = 'tests/data/data.txt'
        client_file = 'tests/data/out.txt'

        h1, h2 = self.net.get('h1', 'h2')

        address = '{}:8888'.format(h1.IP())

        h1.cmdPrint(
            '{} -mserve_file --accept {} --file {} &'
            .format(config.PYTHON, address, server_file)
        )
        # wait_for(partial(is_port_open, address, h1))
        h2.cmdPrint(
            '{} -mserve_file --dial {} --file {}'
            .format(config.PYTHON, address, client_file)
        )
        status = int(h2.cmd('echo $?'))

        self.assertEqual(status, 0)

        self.assertTrue(os.path.isfile(client_file))

        hashes = set(
            file_hashes(server_file, client_file).values()
        )

        self.assertEqual(len(hashes), 1)

    def tearDown(self):
        self.net.stop()
        shutil.rmtree('tests/data/tmp-data')
