<?php

defined('BASEPATH') OR exit('No direct script access allowed');
class Student extends CI_Controller {

  function __construct(){

    parent::__construct();

    $this->load->model('tutor_model', 'tutor');
    $this->load->model('jwt_model', 'jwt');
    $this->load->model('Evaluation_model', 'evaluation');
  }



public function getClasses(){

  if($this->jwt->getToken() &&  $this->jwt->getToken()[0]->position === 'Student'){

      $user = $this->jwt->getToken()[0];

      $tutors = $this->tutor->showAll();


      $studentTutors = array();
      foreach($tutors as $tutor){

        $tutorSchedules = json_decode($tutor->class_schedule);
        if($tutorSchedules){
        foreach($tutorSchedules as $schedule){

          if($schedule->schedule->conn_id === $user->conn_id && $schedule->active === true){




          $newArray = array(

            'tutor' => $tutor,
            'schedule' => $schedule->schedule,



          );
          $studentTutors[] = $newArray;


        }
      }
    }

  }

    if( $studentTutors){

  echo json_encode(array('tutors' => $studentTutors));
    }




}
}


public function getDailyClasses(){


  $getDate = $this->input->post('setDate');
  $getWeekDay = $this->input->post('setWeekDay');

  if($this->jwt->getToken() &&  $this->jwt->getToken()[0]->position === 'Student' && $getDate && $getWeekDay){



      $user = $this->jwt->getToken()[0];

      $tutors = $this->tutor->showAll();


      $studentTutors = array();
      foreach($tutors as $tutor){

        $tutorSchedules = json_decode($tutor->class_schedule);
        if($tutorSchedules){
        foreach($tutorSchedules as $schedule){

          $count =   $schedule->schedule->class_end ? count(explode(',' , json_decode($schedule->schedule->class_end))) : 0;
          $contract_end   =    $count  > 1 ? explode(',' , json_decode($schedule->schedule->class_end))[$count-1] : $schedule->schedule->class_end ;



          $setDateFormat =   str_replace("/", "-", date_format(new DateTime($contract_end), "Y/m/d"));

          $dateExists = date($setDateFormat)  >=  date($getDate);



          $applicableDays = explode(',', json_decode($schedule->schedule->applicable_days ));

          $weekDayExists = in_array($getWeekDay, $applicableDays);




          if($schedule->schedule->conn_id === $user->conn_id && $schedule->active === true && $dateExists && $weekDayExists){

            $schedule->schedule->cancelled_class = property_exists($schedule, 'cancelled_class') ? $schedule->cancelled_class : '';
            $schedule->schedule->cancelled = property_exists($schedule, 'cancelled') ? $schedule->cancelled : '';


          $newArray = array(

            'tutor' => $tutor,
            'schedule' => $schedule->schedule,





          );
          $studentTutors[] = $newArray;


        }
      }
    }

  }



  echo json_encode(array('tutors' => $studentTutors ? $studentTutors : [] ));





}
}

public function getTutors(){

  if($this->jwt->getToken() &&  $this->jwt->getToken()[0]->position === 'Student'){

      $user = $this->jwt->getToken()[0];

      $tutors = $this->tutor->showAll();


      $studentTutors = array();
      foreach($tutors as $tutor){

        $tutorSchedules = json_decode($tutor->class_schedule);
        if($tutorSchedules){
        foreach($tutorSchedules as $schedule){

          if($schedule->schedule->conn_id === $user->conn_id && $schedule->active === true){


          $studentTutors[] = $tutor;


        }
      }
    }

  }

    if( $studentTutors){

  echo json_encode(array('tutors' => $studentTutors, 'student' => $user));
    }




}
}



}
