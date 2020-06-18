<?php

class Faq_model extends CI_Model {

  public function showAll(){


    $query = $this->db->get('faq');

    if($query->num_rows() > 0){

      return $query->result();
    }

    else{

      return false;
    }
  }




  public function getFaq($faqid){

    $this->db->where('faqid', $faqid);
    $query = $this->db->get('faq');



    if($query->num_rows() > 0){

      return $query->result();
    }

    else{

      return false;
    }
    }






  public function addFaq($data){


  return $this->db->insert('faq', $data);


  }



  public function updateFaq($faqid, $field){

     $this->db->where('faqid', $faqid);




    $this->db->update('faq', $field);
    if($this->db->affected_rows() > 0){

      return true;
    }

    else{

      return false;
    }
  }

  public function deleteFaq($faqid){

    $this->db->where('faqid', $faqid);
    $this->db->delete('faq');
    if($this->db->affected_rows() > 0){

      return true;
    }

    else{

      return false;
    }
  }









}
