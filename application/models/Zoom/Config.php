<?php
require_once 'vendor/autoload.php';
class Config {

protected $CLIENT_ID;
protected $CLIENT_SECRET;
protected $REDIRECT_URI;

public function __construct(){


$this->CLIENT_ID = 'f2F8vtrBRYiSDr7EMWeSQg';
$this->CLIENT_SECRET = 'ZUkoQIlTjZOCiCNwokdi0IKWHFGd6u2J';
$this->REDIRECT_URI = 'Callback.php';



}

public function GET_CLIENT_ID(){

  return $this->CLIENT_ID ;
}

public function GET_CLIENT_SECRET(){

  return $this->CLIENT_SECRET;

}

public function GET_REDIRECT_URI(){

  return $this->REDIRECT_URI;
}

}

?>
