<?php

require APPPATH  . '/models/Zoom/Config.php';


class Execute {

  protected $url;


public function __construct(){

$config = new Config;

$this->url  = "https://zoom.us/oauth/authorize?response_type=code&client_id=".$config->GET_CLIENT_ID()."&redirect_uri=".$config->GET_REDIRECT_URI();

}

public function getUrl(){

  return $this->url;
}





}
