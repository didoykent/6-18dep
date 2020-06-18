<<?php

class Leveltest_model extends CI_Model{

public function showAll(){


  $query = $this->db->get('leveltest');

  if($query->num_rows() > 0){

    return $query->result();
  }

  else{

    return false;
  }
}


public function addLevelTest($data){



  return $this->db->insert('leveltest', $data);
}

public function updateLevelTest($idx, $field){

  $this->db->where('idx', $idx);
  $this->db->update('leveltest', $field);
  if($this->db->affected_rows() > 0){

    return true;
  }

  else{

    return false;
  }
}

public function deleteLevelTest($idx){

  $this->db->where('idx', $idx);
  $this->db->delete('leveltest');
  if($this->db->affected_rows() > 0){

    return true;
  }

  else{

    return false;
  }
}


}
