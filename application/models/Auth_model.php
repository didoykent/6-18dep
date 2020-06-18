<<?php

class Auth_model extends CI_Model{


  public function signIn($data){

    

    $query = $this->db->get_where('regularclass', array('id' => $data['id'], 'pw' => $data['pw']));

  $result = $query->result_array();

  if($result){


    return $result;
  }

  else{

    return false;
  }



  }




}
