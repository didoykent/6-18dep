<?php

class Evaluation_model extends CI_Model {

  public function showAll(){


    $query = $this->db->get('evaluation');

    if($query->num_rows() > 0){

      return $query->result();
    }

    else{

      return false;
    }
  }

  public function getEvaluation_by_preference_number($preference_number){

    $this->db->where('preference_number', $preference_number);
    $query = $this->db->get('evaluation');



    if($query->num_rows() > 0){

      return $query->result();
    }

    else{

      return false;
    }
  }


  public function getEvaluation($classid){

    $this->db->where('classid', $classid);
    $query = $this->db->get('evaluation');



    if($query->num_rows() > 0){

      return $query->result();
    }

    else{

      return false;
    }
    }

    public function getleveltestEvaluation($preference_number){

      $this->db->where('preference_number', $preference_number)->where('type', 'leveltest');
      $query = $this->db->get('evaluation');



      if($query->num_rows() > 0){

        return $query->result();
      }

      else{

        return false;
      }
    }


  public function addEvaluation($data){

    $evaluationExists = false;
    $this->db->where('classid', $data['classid']);
    $query = $this->db->get('evaluation');

    if($query->num_rows() > 0){

      $result = $query->result_array()[0];


        $evaluation = json_decode($result['evaluation']);
        $checkEval = json_decode($data['evaluation']);

        if($evaluation && $checkEval){
        foreach ($evaluation as $key => $value) {

            if(date(json_decode($value)->date) === date($checkEval->date)){

                  $evaluation[$key] = $data['evaluation'];

                $evaluationExists = true;
            }
          }

          if($evaluationExists === false){

          $evaluation[] = $data['evaluation'];

        }
}
else{


        $evaluation[] = $data['evaluation'];

      }

        $newData = array(

          'evaluation' => json_encode($evaluation)

        );

        return $this->db->update('evaluation', $newData);



    }

    else{

      $setEvaluation = array();



      $setEvaluation[] = $data['evaluation'];

      $data['evaluation'] = json_encode($setEvaluation);

        return $this->db->insert('evaluation', $data);


    }


  }



  public function updateEvaluation($idx, $field){

    $this->db->where('idx', $idx);
    $this->db->update('evaluation', $field);
    if($this->db->affected_rows() > 0){

      return true;
    }

    else{

      return false;
    }
  }

  public function deleteEvaluation($idx){

    $this->db->where('idx', $idx);
    $this->db->delete('evaluation');
    if($this->db->affected_rows() > 0){

      return true;
    }

    else{

      return false;
    }
  }


  public function addLevelTestEvaluation($data, $classData){


    $checkExecution1 = false;
    $checkExecution2 = false;

      $evaluationExists = false;

    $this->db->where('classid', $data['classid']);
    $query = $this->db->get('evaluation');

    if($query->num_rows() > 0){

      $result = $query->result_array()[0];


        $evaluation = json_decode($result['evaluation']);
        $checkEval = json_decode($data['evaluation']);

        if($evaluation && $checkEval){
        foreach ($evaluation as $key => $value) {

            if(date(json_decode($value)->date) === date($checkEval->date)){

                  $evaluation[$key] = $data['evaluation'];

                $evaluationExists = true;
            }
          }

          if($evaluationExists === false){

          $evaluation[] = $data['evaluation'];

        }
}
else{


        $evaluation[] = $data['evaluation'];

      }

        $newData = array(

          'evaluation' => json_encode($evaluation)

        );

        if($this->db->update('evaluation', $newData)){

            $checkExecution1 = true;
        }
    }

    else{

      $setEvaluation = array();

      $setEvaluation[] = $data['evaluation'];

      $data['evaluation'] = json_encode($setEvaluation);

        if( $this->db->insert('evaluation', $data)){

            $checkExecution1 = true;
        }


    }


$query = $this->db->get('uedu_tutor');

if($query->num_rows() > 0){

  $result = $query->result();


  foreach($result as $tutor){


    $schedules = json_decode($tutor->class_schedule);


    if($schedules){

      foreach($schedules as $k => $schedule){

        if($schedule->schedule->classid ===  $data['classid']){

            $schedules[$k]->schedule->Level = $classData['Level'];
            $schedules[$k]->schedule->Curriculum = $classData['Curriculum'];
            $schedules[$k]->schedule->Material = $classData['Material'];



            $newClassData = array(

              'class_schedule' => json_encode($schedules)
            );
            $this->db->where('idx', $tutor->idx);
          if($this->db->update('uedu_tutor', $newClassData)){

              $checkExecution2 = true;
          }

        }
      }
    }

  }





}


if($checkExecution1 === true && $checkExecution2 === true){
    return true;
}
  }


  public function get_student_evaluations($phone_number){


    $this->db->where('phone_number', $phone_number)->where('type', 'regularclass');
    $query = $this->db->get('evaluation');



    if($query->num_rows() > 0){

      return $query->result();
    }

    else{

      return false;
    }

  }



}
