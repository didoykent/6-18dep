<<?php

class Regularclass_model extends CI_Model{


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


public function showAll(){



  $query = $this->db->get('regularclass');

  if($query->num_rows() > 0){

    return $query->result();
  }

  else{

    return false;
  }
}

public function addRegularClass($data){



  return $this->db->insert('regularclass', $data);
}

public function updateRegularClass($conn_id, $field){

  $this->db->where('conn_id', $conn_id);
  $this->db->update('regularclass', $field);
  if($this->db->affected_rows() > 0){

    return true;
  }

  else{

    return false;
  }
}

public function deleteRegularClass($idx){

  $this->db->where('idx', $idx);
  $this->db->delete('regularclass');
  if($this->db->affected_rows() > 0){

    return true;
  }

  else{

    return false;
  }
}


}
