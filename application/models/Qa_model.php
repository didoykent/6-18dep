<?php

class Qa_model extends CI_Model {

  public function showAll(){


    $query = $this->db->get('qa');

    if($query->num_rows() > 0){

      return $query->result();
    }

    else{

      return false;
    }
  }




  public function getQa($student_idx){

    $this->db->where('student_idx', $student_idx);
    $query = $this->db->get('qa');



    if($query->num_rows() > 0){

      return $query->result();
    }

    else{

      return false;
    }
    }






  public function addQa($data){


    $this->db->where('student_idx', $data['student_idx']);
    $query = $this->db->get('qa');

    if($query->num_rows() > 0){

      $result = $query->result_array()[0];


        $qa = json_decode($result['qa']);

          if($qa){
        $qa[] = $data['qa'];



        $newData = array(

          'qa' => json_encode($qa)

        );

        return $this->db->update('qa', $newData);

}

    }

    else{

      $setqa = array();



      $setqa[] = $data['qa'];

      $data['qa'] = json_encode($setqa);

        return $this->db->insert('qa', $data);


    }


  }



  public function updateQa($student_idx, $field){

    $this->db->where('student_idx', $student_idx);
    $this->db->update('qa', $field);
    if($this->db->affected_rows() > 0){

      return true;
    }

    else{

      return false;
    }
  }

  public function deleteQa($idx){

    $this->db->where('idx', $idx);
    $this->db->delete('qa');
    if($this->db->affected_rows() > 0){

      return true;
    }

    else{

      return false;
    }
  }









}
