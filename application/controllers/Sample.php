<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Sample extends CI_Controller {
	public function index() {
		require_once APPPATH . 'libraries/codeigniter-predis/src/Redis.php';

        echo '<pre>';

        echo 'See application/config/codeigniter-predis.php file <br><br>';

        // Using the default_server configuration
        $this->redis = new \CI_Predis\Redis();
        echo 'PING server setted to default_server config param: ';
        echo $this->redis->ping() . '<br><br>';
        echo 'PING server setted to default_server config param, another way: ';
        echo $this->redis->getServerConnected()->ping() . '<br><br>';





		// Calling a command in a not connected server
        //echo 'PING a not connected server: <br>';
        // $this->redis->getServersCollection()->getServer('not_connected_server')->ping() . '<br>';
	}
}
