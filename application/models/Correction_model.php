<?php

class Correction_model extends CI_Model {

  public function showAll(){


    $query = $this->db->get('correction');

    if($query->num_rows() > 0){

      return $query->result();
    }

    else{

      return false;
    }
  }




  public function getCorrection($student_idx){

    $this->db->where('student_idx', $student_idx);
    $query = $this->db->get('correction');



    if($query->num_rows() > 0){

      return $query->result();
    }

    else{

      return false;
    }
    }

    public function getTutorCorrection($conn_id){


      $corrections = $this->showAll();


      return $corrections;


    }




  public function addcorrection($data){


    $this->db->where('student_idx', $data['student_idx']);
    $query = $this->db->get('correction');

    if($query->num_rows() > 0){

      $result = $query->result_array()[0];


        $correction = json_decode($result['correction']);

          if($correction){
        $correction[] = $data['correction'];



        $newData = array(

          'correction' => json_encode($correction)

        );

        return $this->db->update('correction', $newData);

}

    }

    else{

      $setcorrection = array();



      $setcorrection[] = $data['correction'];

      $data['correction'] = json_encode($setcorrection);

        return $this->db->insert('correction', $data);


    }


  }



  public function updatecorrection($student_idx, $field){

    $this->db->where('student_idx', $student_idx);
    $this->db->update('correction', $field);
    if($this->db->affected_rows() > 0){

      return true;
    }

    else{

      return false;
    }
  }

  public function deletecorrection($idx){

    $this->db->where('idx', $idx);
    $this->db->delete('correction');
    if($this->db->affected_rows() > 0){

      return true;
    }

    else{

      return false;
    }
  }









}
