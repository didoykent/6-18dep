<?php

interface MessageInterface   {


public function create( $sender, $receiver, $message);

public function get($sender, $receiver);




}

 ?>
