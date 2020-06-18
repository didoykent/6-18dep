<?php

class Oath_model extends CI_Model {


public function get_access_token(){
  $query = $this->db->get('token');

  if($query->num_rows() > 0){

    return $query->result();
  }

  else{

    return false;
  }

}




}
