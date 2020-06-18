<?php

class Announcement_model extends CI_Model {

  public function showAll(){


    $query = $this->db->get('announcement');

    if($query->num_rows() > 0){

      return $query->result();
    }

    else{

      return false;
    }
  }




  public function getAnnouncement($category){

    $this->db->where('category', $category);
    $query = $this->db->get('announcement');



    if($query->num_rows() > 0){

      return $query->result();
    }

    else{

      return false;
    }
    }

    public function getAnnouncements($conn_id){


      $announcements = $this->showAll();


      return $announcements;


    }




  public function addAnnouncement($data){






        return $this->db->insert('announcement', $data);





  }



  public function updateAnnouncement($announcement_id, $field){

    $this->db->where('announcement_id', $announcement_id);
    $this->db->update('announcement', $field);
    if($this->db->affected_rows() > 0){

      return true;
    }

    else{

      return false;
    }
  }

  public function deleteAnnouncement($announcement_id){

    $this->db->where('announcement_id', $announcement_id);
    $this->db->delete('announcement');
    if($this->db->affected_rows() > 0){

      return true;
    }

    else{

      return false;
    }
  }









}
