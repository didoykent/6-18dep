<?php

class Academy_model extends CI_Model {

  public function showAll(){


    $query = $this->db->get('academy');

    if($query->num_rows() > 0){

      return $query->result();
    }

    else{

      return false;
    }
  }




  public function getAcademy($academyid){

    $this->db->where('academyid', $academyid);
    $query = $this->db->get('academy');



    if($query->num_rows() > 0){

      return $query->result();
    }

    else{

      return false;
    }
    }






  public function addAcademy($data){


  return $this->db->insert('academy', $data);


  }



  public function updatAacademy($academyid, $field){

     $this->db->where('academyid', $academyid);




    $this->db->update('academy', $field);
    if($this->db->affected_rows() > 0){

      return true;
    }

    else{

      return false;
    }
  }

  public function deleteAcademy($academyid){

    $this->db->where('academyid', $academyid);
    $this->db->delete('academy');
    if($this->db->affected_rows() > 0){

      return true;
    }

    else{

      return false;
    }
  }









}
