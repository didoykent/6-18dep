<?php

class Tutor_model extends CI_Model{





public function showAll(){


  $query = $this->db->get('uedu_tutor');

  if($query->num_rows() > 0){

    return $query->result();
  }

  else{

    return false;
  }
}


public function addTutor($data){

  return $this->db->insert('uedu_tutor', $data);
}







public function updateTutor($idx, $field){

  $this->db->where('idx', $idx);
  $this->db->update('uedu_tutor', $field);
  if($this->db->affected_rows() > 0){

    return true;
  }

  else{

    return false;
  }
}

public function deleteTutor($idx){

  $this->db->where('idx', $idx);
  $this->db->delete('uedu_tutor');
  if($this->db->affected_rows() > 0){

    return true;
  }

  else{

    return false;
  }
}



public function addClass($tutor, $data){





    $this->db->where('idx', $tutor);
    $query = $this->db->get('uedu_tutor');




$result = $query->result_array();



   $tempArray = array();


$tempArray['active'] = true;





   $tempArray['type'] = $data['class_type'];
   $tempArray['schedule'] = $data;
   $tempArray['cancelled_class'] = array();
   $tempArray['cancelled'] = false;






$newArray = array();


if($result){

  if($result[0]['class_schedule']){

   foreach (json_decode($result[0]['class_schedule']) as $key ) {

     $newArray[]  =  $key;



   }

   $newArray[] =  $tempArray;

 }

 else{


   $newArray[] = $tempArray;

 }

}

else{

  return;
}















   $newData = array(

     'class_schedule' => json_encode($newArray)

   );


   $this->db->where('idx', $tutor);

   $this->db->update('uedu_tutor', $newData);



   if($this->db->affected_rows() > 0){

     return true;
   }

   else{

     return false;
   }


}


public function signIn($data){

  $query = $this->db->get_where('uedu_tutor', array('id' => $data['id'], 'pw' => $data['pw']));

$result = $query->result_array();

if($result){


  return $result;
}

else{

  return false;
}



}


public function getTutor($idx){

  $this->db->where('idx', $idx);
  $query = $this->db->get('uedu_tutor');



  if($query->num_rows() > 0){

    return $query->result();
  }

  else{

    return false;
  }
  }

  public function get_tutor_by_conn($conn_id){

    $this->db->where('conn_id', $conn_id);
    $query = $this->db->get('uedu_tutor');



    if($query->num_rows() > 0){

      return $query->result();
    }

    else{

      return false;
    }
    }


  public function get_team_members($team){

    $this->db->where('team', $team);
    $query = $this->db->get('uedu_tutor');



    if($query->num_rows() > 0){

      return $query->result();
    }

    else{

      return false;
    }
  }

  public function get_team_members_monitoring($team_monitoring){

    $this->db->where('team_monitoring', $team_monitoring);
    $query = $this->db->get('uedu_tutor');



    if($query->num_rows() > 0){

      return $query->result();
    }

    else{

      return false;
    }

  }







}
