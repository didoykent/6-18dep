<?php

defined('BASEPATH') OR exit('No direct script access allowed');
class Tutor extends CI_Controller {

  function __construct(){

    parent::__construct();

    $this->load->model('tutor_model', 'tutor');
    $this->load->model('jwt_model', 'jwt');
    $this->load->model('Evaluation_model', 'evaluation');
  }

  function connid_key() {
          $this->load->library('uuid');
          $id = $this->uuid->v4();
          return $id;
  }

  public function index(){


    $this->load->view('welcome_message');
  }

  public function uploadFile(){

              $config['upload_path']          = './uploads/';
              $config['allowed_types']        = 'mp4|mp3';
              $config['max_size']             = 100;


              $this->load->library('upload', $config);

              if ( ! $this->upload->do_upload('files'))
              {
                      $error = array('error' => $this->upload->display_errors());

                      echo json_encode(array('success' => $error));
              }
              else
              {
                      $data = array('upload_data' => $this->upload->data());

                          echo json_encode(array('success' => true));
              }
  }




  public function showAll(){

    $query = $this->tutor->showAll();

    if($query){

      $result['tutors'] = $this->tutor->showAll();
    }

    echo json_encode($result);
  }

  public function addManager(){

    $config = array(

      array(
        'field' => 'id',
        'label' => 'Id',
        'rules' => 'trim|required'
      ),

      array(
        'field' => 'pw',
        'label' => 'Password',
        'rules' => 'trim|required'
      ),

      array(
        'field' => 'mega_name',
        'label' => 'Meganame',
        'rules' => 'trim|required'
      ),

      array(
        'field' => 'position',
        'label' => 'Position',
        'rules' => 'trim|required'
      ),

      array(
       'field' => 'first_name',
       'label' => 'Firstname',
       'rules' => 'trim|required'
      ),

      array(
        'field' => 'last_name',
        'label' => 'Lastname',
        'rules' => 'trim|required'
      ),

      array(
        'field' => 'sex',
        'Label' => 'Sex',
        'rules' => 'trim|required'
      ),

      array(
        'field' => 'date_of_birth',
        'label' => 'DateOfBirth',
        'rules' => 'trim|required',
      ),

      array(
        'field' => 'address',
        'label' => 'Address',
        'rules' => 'trim|required'
      ),

      array(
        'field' => 'major',
        'Label' => 'Major',
        'rules' => 'trim|required'
      ),

      array(
        'field' => 'school',
        'label' => 'School',
        'rules' => 'trim|required'
      ),

      array(
        'field' => 'workexp',
        'label' => 'Workexperience',
        'rules' => 'trim|required'
      ),

      array(
        'field' => 'introduction',
        'label' => 'Introduction',
        'rules' => 'trim|required'
      ),

      array(
        'field' => 'mobile_number',
        'label' => 'Mobilenumber',
        'rules' => 'trim|required'
      ),

      array(
        'field' => 'email',
        'label' => 'Email',
        'rules' => 'trim|required|valid_email',
      ),

      array(
        'field' => 'specialty',
        'label' => 'Specialty',
        'rules' => 'trim|required'

      ),

      array(
        'field' => 'start_am',
        'label' => 'Startam',
        'rules' => 'trim|required'

      ),

      array(
        'field' => 'end_pm',
        'label' => 'Endpm',
        'rules' => 'trim|required'

      ),


    );

    $this->form_validation->set_rules($config);

    if($this->form_validation->run() === FALSE){

$result['error'] = true;
$result['msg'] = array(
  'id' => form_error('id'),
  'pw' => form_error('pw'),
  'mega_name' => form_error('mega_name'),
  'position' => form_error('position'),
  'first_name' => form_error('first_name'),
  'last_name' => form_error('last_name'),
  'sex' => form_error('sex'),
  'date_of_birth' => form_error('date_of_birth'),
  'address' => form_error('address'),
  'major' => form_error('major'),
  'school' => form_error('school'),
  'workexp' => form_error('workexp'),
  'introduction' => form_error('introduction'),
  'mobile_number' => form_error('mobile_number'),
  'email' => form_error('email'),
  'specialty' => form_error('specialty'),
  'start_am' => form_error('start_am'),
  'end_pm' => form_error('end_pm'),



);

    }

    else{






      $data = array(
        'id' => $this->input->post('id'),
        'pw' => $this->input->post('pw'),
        'mega_name' => $this->input->post('mega_name'),
        'position' => $this->input->post('position'),
        'first_name' => $this->input->post('first_name'),
        'last_name' => $this->input->post('last_name'),
        'sex' => $this->input->post('sex'),
        'date_of_birth' => $this->input->post('date_of_birth'),
        'address' => $this->input->post('address'),
        'major' => $this->input->post('major'),
        'school' => $this->input->post('school'),
        'workexp' => json_encode($this->input->post('workexp')),
        'introduction' => $this->input->post('introduction'),
        'mobile_number' => $this->input->post('mobile_number'),
        'email' => $this->input->post('email'),
        'specialty' => $this->input->post('specialty'),
        'start_am' => $this->input->post('start_am'),
        'end_pm' => $this->input->post('end_pm'),
        'team' => $this->input->post('team'),



      );



      if($this->tutor->addTutor($data)){
        $result['error'] = false;
        $result['msg'] = 'Tutor added successfully';

      }

      else{

        $result['error'] = true;
        $result['msg'] = 'Data creation failed';

      }
    }

    echo json_encode($result);



  }


  public function addTutor(){

    $config = array(

      array(
        'field' => 'id',
        'label' => 'Id',
        'rules' => 'trim|required'
      ),

      array(
        'field' => 'pw',
        'label' => 'Password',
        'rules' => 'trim|required'
      ),

      array(
        'field' => 'mega_name',
        'label' => 'Meganame',
        'rules' => 'trim|required'
      ),

      array(
        'field' => 'position',
        'label' => 'Position',
        'rules' => 'trim|required'
      ),

      array(
       'field' => 'first_name',
       'label' => 'Firstname',
       'rules' => 'trim|required'
      ),

      array(
        'field' => 'last_name',
        'label' => 'Lastname',
        'rules' => 'trim|required'
      ),

      array(
        'field' => 'sex',
        'Label' => 'Sex',
        'rules' => 'trim|required'
      ),

      array(
        'field' => 'date_of_birth',
        'label' => 'DateOfBirth',
        'rules' => 'trim|required',
      ),

      array(
        'field' => 'address',
        'label' => 'Address',
        'rules' => 'trim|required'
      ),

      array(
        'field' => 'major',
        'Label' => 'Major',
        'rules' => 'trim|required'
      ),

      array(
        'field' => 'school',
        'label' => 'School',
        'rules' => 'trim|required'
      ),

      array(
        'field' => 'workexp',
        'label' => 'Workexperience',
        'rules' => 'trim|required'
      ),

      array(
        'field' => 'introduction',
        'label' => 'Introduction',
        'rules' => 'trim|required'
      ),

      array(
        'field' => 'mobile_number',
        'label' => 'Mobilenumber',
        'rules' => 'trim|required'
      ),

      array(
        'field' => 'email',
        'label' => 'Email',
        'rules' => 'trim|required|valid_email',
      ),

      array(
        'field' => 'specialty',
        'label' => 'Specialty',
        'rules' => 'trim|required'

      ),

      array(
        'field' => 'am',
        'label' => 'Am',
        'rules' => 'trim|required'

      ),

      array(
        'field' => 'pm',
        'label' => 'Pm',
        'rules' => 'trim|required'

      ),

      array(
        'field' => 'workplace',
        'label' => 'Workplace',
        'rules' => 'trim|required'

      ),

      array(
        'field' => 'start_am',
        'label' => 'Startam',
        'rules' => 'trim|required'

      ),

      array(
        'field' => 'end_am',
        'label' => 'Endam',
        'rules' => 'trim|required'

      ),

      array(
        'field' => 'start_pm',
        'label' => 'Startpm',
        'rules' => 'trim|required'

      ),

      array(
        'field' => 'end_pm',
        'label' => 'Endpm',
        'rules' => 'trim|required'

      ),


      array(
        'field' => 'affiliation',
        'label' => 'Affiliation',
        'rules' => 'trim|required'

      ),

      array(
        'field' => 'language',
        'label' => 'Language',
        'rules' => 'trim|required'

      ),

      array(
        'field' => 'class_type',
        'label' => 'Classtype',
        'rules' => 'trim|required'

      ),

      array(
        'field' => 'academies',
        'label' => 'Academies',
        'rules' => 'trim|required'

      ),

      array(
        'field' => 'starting_date',
        'label' => 'Startingdate',
        'rules' => 'trim|required'

      ),

      array(
        'field' => 'country',
        'label' => 'Country',
        'rules' => 'trim|required'

      )

    );

    $this->form_validation->set_rules($config);

    if($this->form_validation->run() === FALSE){

$result['error'] = true;
$result['msg'] = array(
  'id' => form_error('id'),
  'pw' => form_error('pw'),
  'mega_name' => form_error('mega_name'),
  'position' => form_error('position'),
  'first_name' => form_error('first_name'),
  'last_name' => form_error('last_name'),
  'sex' => form_error('sex'),
  'date_of_birth' => form_error('date_of_birth'),
  'address' => form_error('address'),
  'major' => form_error('major'),
  'school' => form_error('school'),
  'workexp' => form_error('workexp'),
  'introduction' => form_error('introduction'),
  'mobile_number' => form_error('mobile_number'),
  'email' => form_error('email'),
  'specialty' => form_error('specialty'),
  'am' => form_error('am'),
  'pm' => form_error('pm'),
  'workplace' => form_error('workplace'),
  'start_am' => form_error('start_am'),
  'end_am' => form_error('end_am'),
  'start_pm' => form_error('start_pm'),
  'end_pm' => form_error('end_pm'),
  'affiliation' => form_error('affiliation'),
  'language' => form_error('language'),
  'class_type' => form_error('class_type'),
  'academies' => form_error('academies'),
  'starting_date' => form_error('starting_date'),
  'country' => form_error('country')

);

    }

    else{


      $file_name = '';




          $config['upload_path']          = './uploads/';
          $config['allowed_types']        = 'mp4|mp3';
          $config['max_size']             = 100;


          $this->load->library('upload', $config);

          if ( ! $this->upload->do_upload('files'))
          {
                  $error = array('error' => $this->upload->display_errors());

                  $result['error'] = true;
                  $result['msg'] = $error;
          }
          else
          {
                  $data = array('upload_data' => $this->upload->data());
                  $file_name = $data['upload_data']['file_name'];
                  $result['error'] = false;
                  $result['msg'] = 'successfully uploaded file';
          }

      $data = array(
        'id' => $this->input->post('id'),
        'pw' => $this->input->post('pw'),
        'mega_name' => $this->input->post('mega_name'),
        'position' => $this->input->post('position'),
        'first_name' => $this->input->post('first_name'),
        'last_name' => $this->input->post('last_name'),
        'sex' => $this->input->post('sex'),
        'date_of_birth' => $this->input->post('date_of_birth'),
        'address' => $this->input->post('address'),
        'major' => $this->input->post('major'),
        'school' => $this->input->post('school'),
        'workexp' => json_encode($this->input->post('workexp')),
        'introduction' => $this->input->post('introduction'),
        'mobile_number' => $this->input->post('mobile_number'),
        'email' => $this->input->post('email'),
        'specialty' => $this->input->post('specialty'),
        'am' => $this->input->post('am'),
        'pm' => $this->input->post('pm'),
        'workplace' => $this->input->post('workplace'),
        'start_am' => $this->input->post('start_am'),
        'end_am' => $this->input->post('end_am'),
        'start_pm' => $this->input->post('start_pm'),
        'end_pm' => $this->input->post('end_pm'),
        'affiliation' => $this->input->post('affiliation'),
        'language' => $this->input->post('language'),
        'class_type' => json_encode($this->input->post('class_type')),
        'academies' => json_encode($this->input->post('academies')),
        'starting_date' => $this->input->post('starting_date'),
        'country' => $this->input->post('country'),
        'team' => $this->input->post('team'),
        'recording_path' => $file_name,
        'conn_id' => $this->connid_key()

      );



      if($this->tutor->addTutor($data)){
        $result['error'] = false;
        $result['msg'] = 'Tutor added successfully';

      }

      else{

        $result['error'] = true;
        $result['msg'] = 'Data creation failed';

      }
    }

    echo json_encode($file_name);

  }

  public function updateTutor(){


    $config = array(






      array(
        'field' => 'mega_name',
        'label' => 'Meganame',
        'rules' => 'trim|required'
      ),

      array(
        'field' => 'position',
        'label' => 'Position',
        'rules' => 'trim|required'
      ),

      array(
       'field' => 'first_name',
       'label' => 'Firstname',
       'rules' => 'trim|required'
      ),

      array(
        'field' => 'last_name',
        'label' => 'Lastname',
        'rules' => 'trim|required'
      ),

      array(
        'field' => 'sex',
        'Label' => 'Sex',
        'rules' => 'trim|required'
      ),

      array(
        'field' => 'date_of_birth',
        'label' => 'DateOfBirth',
        'rules' => 'trim|required',
      ),

      array(
        'field' => 'address',
        'label' => 'Address',
        'rules' => 'trim|required'
      ),

      array(
        'field' => 'major',
        'Label' => 'Major',
        'rules' => 'trim|required'
      ),

      array(
        'field' => 'school',
        'label' => 'School',
        'rules' => 'trim|required'
      ),

      array(
        'field' => 'workexp',
        'label' => 'Workexperience',
        'rules' => 'trim|required'
      ),

      array(
        'field' => 'introduction',
        'label' => 'Introduction',
        'rules' => 'trim|required'
      ),

      array(
        'field' => 'mobile_number',
        'label' => 'Mobilenumber',
        'rules' => 'trim|required'
      ),

      array(
        'field' => 'email',
        'label' => 'Email',
        'rules' => 'trim|required|valid_email',
      ),

      array(
        'field' => 'specialty',
        'label' => 'Specialty',
        'rules' => 'trim|required'

      ),









    );

    $this->form_validation->set_rules($config);

    if($this->form_validation->run() === FALSE){

    $result['error'] = true;
    $result['msg'] = array(

      'mega_name' => form_error('mega_name'),
      'position' => form_error('position'),
      'first_name' => form_error('first_name'),
      'last_name' => form_error('last_name'),
      'sex' => form_error('sex'),
      'date_of_birth' => form_error('date_of_birth'),
      'address' => form_error('address'),
      'major' => form_error('major'),
      'school' => form_error('school'),
      'workexp' => form_error('workexp'),
      'introduction' => form_error('introduction'),
      'mobile_number' => form_error('mobile_number'),
      'email' => form_error('email'),
      'specialty' => form_error('specialty')



);
    }

    else{
      $file_name = '';




          $config['upload_path']          = './uploads/';
          $config['allowed_types']        = 'mp4|mp3';
          $config['max_size']             = 100;


          $this->load->library('upload', $config);

          if ( ! $this->upload->do_upload('files'))
          {
                  $error = array('error' => $this->upload->display_errors());

                  $result['error'] = true;
                  $result['msg'] = $error;
          }
          else
          {
                  $data = array('upload_data' => $this->upload->data());
                  $file_name = $data['upload_data']['file_name'];
                  $result['error'] = false;
                  $result['msg'] = 'successfully uploaded file';
          }

      $idx = $this->input->post('idx');

      $data = array(

        'mega_name' => $this->input->post('mega_name'),
        'position' => $this->input->post('position'),
        'first_name' => $this->input->post('first_name'),
        'last_name' => $this->input->post('last_name'),
        'sex' => $this->input->post('sex'),
        'date_of_birth' => $this->input->post('date_of_birth'),
        'address' => $this->input->post('address'),
        'major' => $this->input->post('major'),
        'school' => $this->input->post('school'),
        'workexp' => json_encode($this->input->post('workexp')),
        'introduction' => $this->input->post('introduction'),
        'mobile_number' => $this->input->post('mobile_number'),
        'email' => $this->input->post('email'),
        'specialty' => $this->input->post('specialty'),
        'recording_path' => $file_name ? $file_name : $this->input->post('recording_path')


      );

      if($this->tutor->updateTutor($idx, $data)){
        $result['error'] = false;
        $result['msg'] = 'Tutor updated successfully';

      }

      else{

        $result['error'] = true;
        $result['msg'] = 'Data not found update failed';

      }
    }

      echo json_encode($result);

  }

  public function deleteTutor(){

    $idx = $this->input->post('idx');

    if($this->tutor->deleteTutor($idx)){

      $msg['error'] = false;
      $msg['success'] = 'Data deleted successfully';
    }
    else{

      $msg['error'] = true;

    }
    echo json_encode($msg);
  }


  public function getClassSchedule(){


      if($this->jwt->getToken()){
    $currentDate = $this->input->post('currentDate');
      $user = $this->jwt->getToken();

      $tutor =   $this->tutor->getTutor($user[0]->idx);


      $testSchedule =  $tutor;
      $userData = array();

if($tutor[0]->class_schedule){

      foreach(json_decode($tutor[0]->class_schedule) as $daily){

        if($daily->active === true){


          $class_start = explode(',' , json_decode($daily->schedule->class_start))[0] ?   explode(',' , json_decode($daily->schedule->class_start)) : $daily->schedule->class_start;


          if(is_array($class_start)){

              foreach($class_start as $date){

                  $setDate  = str_replace("/", "-", date_format(new DateTime($date), "Y/m/d"));



                  if(date($setDate ) === date($currentDate)){

                    $userData[] = $daily;


                }
              }
          }
          else{

            $dateNow =  str_replace("/", "-", date_format(new DateTime($class_start), "Y/m/d"));
          if(date($dateNow ) === date($currentDate)){

            $userData[] = $daily;


        }

      }
    }
  }


}








$tutor[0]->class_schedule  = json_encode($userData);


      echo json_encode(array('class_schedule' => $tutor[0]->class_schedule, 'tutor' => $tutor[0], 'date' => $currentDate, 'test' => $testSchedule ));

      }
  }


  public function getClasses(){

      if($this->jwt->getToken()){

          $tutor = $this->jwt->getToken();

          $tutor =   $this->tutor->getTutor($tutor[0]->idx);

            if($tutor[0]->class_schedule){


              echo json_encode(array('schedule' => $tutor[0]->class_schedule, 'tutor' => $tutor[0]));
            }
      }


  }


  public function getAllStudents(){



    if($this->jwt->getToken()){




        $Tutors =   $this->tutor->showAll();
        $students = array();

        foreach($Tutors as $tutor){



          $schedules  = json_decode($tutor->class_schedule);
          if($schedules){
          foreach($schedules as $schedule){
            if($schedule->schedule->category === 'regularclass' && $schedule->active === true){
            $students[] = $schedule->schedule;
          }
          }
        }

        }

foreach($students as $k => $student){

  if(!empty($students[$k-1])){

    if($student->id ===  $students[$k-1]->id){

        unset($students[$k-1]);
    }
  }
}


    echo json_encode( array_unique($students, SORT_REGULAR));

    }


  }



  public function getLevelTestStudents(){


    if($this->jwt->getToken()){


        $Tutors =   $this->tutor->showAll();
        $students = array();

        foreach($Tutors as $tutor){



          $schedules  = json_decode($tutor->class_schedule);
          if($schedules){
          foreach($schedules as $schedule){
            if($schedule->schedule->category === 'leveltest' && $schedule->active === true){
              $schedule->schedule->tutor_name = $tutor->mega_name;
              $schedule->schedule->tutor_idx = $tutor->idx;
            $students[] = $schedule->schedule;
          }
          }
        }

        }

foreach($students as $k => $student){

  if(!empty($students[$k-1])){

    if($student->classid ===  $students[$k-1]->classid){

        unset($students[$k-1]);
    }
  }
}


    echo json_encode( array_unique($students, SORT_REGULAR));

    }



  }





  public function getAllClasses(){

    if($this->jwt->getToken()){


      $classes = array();
        $Tutors =   $this->tutor->showAll();
        $students = array();

        foreach($Tutors as $tutor){

          $temp = array();



          $schedules = json_decode($tutor->class_schedule);



          $temp['schedule'] = json_decode($tutor->class_schedule);


          $temp['tutor'] =  $tutor;

          $classes[] = $temp;
        }


    echo json_encode($classes);

    }

  }






  public function getAvailableTutors(){

    if($this->jwt->getToken()){
      $overlap = false;
      $notOverlap = false;
      $tutors = array();

      $type = false;

      $tutorsWithWarning = array();







      $start_class = $this->input->post('start_class');
      $end_class = $this->input->post('end_class');
      $class_type = $this->input->post('class_type');


      $weekdays = explode(',' , $this->input->post('weekdays'));


      $query = $this->tutor->showAll();

      if($query){

        $result = $this->tutor->showAll();

        for($i =0; $i<count($result); $i++){


        if($result[$i]->class_schedule){

          $checks = json_decode($result[$i]->class_schedule);




          foreach($checks as $k => $check){

            if($check->active === false){

              unset($checks[$k]);
              if(count($checks) <=0){

                $checks = null;
              }
            }
          }

        $result[$i]->class_schedule = is_array($checks) ? json_encode(array_values($checks)) : $checks;

}
        }



        foreach($result as $value){


      if($value->class_schedule){


                  $schedule = json_decode($value->class_schedule);

                  $leveltestSchedule[] = $schedule;

                    if($class_type === 'regularclass'){

                      $start_class =  explode(',' , $this->input->post('start_class'));
                      $end_class =   explode(',' , $this->input->post('end_class'));



                      foreach($schedule as $value2){



                        $class_start= explode(',' , json_decode($value2->schedule->class_start))[0] ?  explode(',' , json_decode($value2->schedule->class_start)) : $value2->schedule->class_start;
                        $class_end=  explode(',' , json_decode($value2->schedule->class_end))[0] ?  explode(',' , json_decode($value2->schedule->class_end)) :  $value2->schedule->class_end;

                            if(is_array($class_start)){




                                for($c = 0; $c<count($class_start); $c++){


                for($d =0; $d<count($start_class); $d++){


                  if(date(  $start_class[$d]) >= date($class_end[$c]) || date($end_class[$d]) < date($class_start[$c] )){



                      $getStartClass =  explode(" ", date(  $start_class[$d]));
                      $getClassStart = explode(" ", date(  $class_start[$c]));
                      $getEndClass = explode(" ", date(  $end_class[$d]));
                      $getClassEnd = explode(" ", date(  $class_end[$c]));
                      $applicableDays = explode(',', json_decode($value2->schedule->applicable_days));




                      $diff = array_diff($applicableDays, $weekdays);


                      if(count($diff) < count($applicableDays)){
                            if(date(  $getStartClass[1]) >= date($getClassEnd[1]) || date($getEndClass[1]) < date($getClassStart[1])){


                            }

                            else{


                              $tutorsWithWarning[] = $value->idx;

                            }

}


                 $notOverlap = true;


                 $tutors[] = $value;



             }

             else{



                 $overlap = true;


                 $tutors = array_unique($tutors, SORT_REGULAR);


                 $value->overlap = true;


                 $tutors[] = $value;

                 break;


               }


                }




              }



                        }


                        else{




                            for($d =0; $d<count($start_class); $d++){


                              if(date(  $start_class[$d]) >= date($class_end) || date($end_class[$d]) < date($class_start )){


                                $getStartClass =  explode(" ", date(  $start_class[$d]));
                                $getClassStart = explode(" ", date(  $class_start));
                                $getEndClass = explode(" ", date(  $end_class[$d]));
                                $getClassEnd = explode(" ", date(  $class_end));
                                $applicableDays = explode(',', json_decode($value2->schedule->applicable_days));




                                $diff = array_diff($applicableDays, $weekdays);


                                if(count($diff) < count($applicableDays)){
                                      if(date(  $getStartClass[1]) >= date($getClassEnd[1]) || date($getEndClass[1]) < date($getClassStart[1])){


                                      }

                                      else{


                                        $tutorsWithWarning[] = $value->idx;

                                      }

          }




                             $notOverlap = true;


                                $tutors[] = $value;






                         }

                         else{




                             $overlap = true;
                             $tutors = array_unique($tutors, SORT_REGULAR);






   $value->overlap = true;

   $tutors[] = $value;

   break;


                           }


                            }





                        }








                      }
                    }

                    else{



                        foreach($schedule  as $value2){




                            $class_start= explode(',' , json_decode($value2->schedule->class_start))[0] ?  explode(',' , json_decode($value2->schedule->class_start)) : $value2->schedule->class_start;
                          $class_end=  explode(',' , json_decode($value2->schedule->class_end))[0] ?  explode(',' , json_decode($value2->schedule->class_end)) :  $value2->schedule->class_end;

                          if(is_array($class_start)){


                          foreach($class_start as $key => $class){



                            if(date($start_class) >= date($class_end[$key]) || date($end_class) < date($class )){


                              $getStartClass =  explode(" ", date($start_class));
                              $getClassStart = explode(" ", date($class));
                              $getEndClass = explode(" ", date($end_class));
                              $getClassEnd = explode(" ", date($class_end[$key]));
                              $applicableDays = explode(',', json_decode($value2->schedule->applicable_days));




                              $diff = array_diff($applicableDays, $weekdays);


                              if(count($diff) < count($applicableDays)){
                                    if(date(  $getStartClass[1]) >= date($getClassEnd[1]) || date($getEndClass[1]) < date($getClassStart[1])){


                                    }

                                    else{


                                      $tutorsWithWarning[] = $value->idx;

                                    }

                    }
                              $notOverlap = true;

                                $tutors[] = $value;

                          }

                          else{

                            $overlap = true;

                            $tutors = array_unique($tutors, SORT_REGULAR);


                        $value->overlap = true;

                        $tutors[] = $value;

                        break;



                          }






                        }

  }

  else{

    if(date($start_class) >= date($class_end) || date($end_class) < date($class_start)){



      $getStartClass =  explode(" ", date( $start_class));
      $getClassStart = explode(" ", date( $class_start));
      $getEndClass = explode(" ", date( $end_class));
      $getClassEnd = explode(" ", date( $class_end));
      $applicableDays = explode(',', json_decode($value2->schedule->applicable_days));




      $diff = array_diff($applicableDays, $weekdays);


      if(count($diff) < count($applicableDays)){
            if(date(  $getStartClass[1]) >= date($getClassEnd[1]) || date($getEndClass[1]) < date($getClassStart[1])){


            }

            else{


              $tutorsWithWarning[] = $value->idx;

            }

    }

      $notOverlap = true;

        $tutors[] = $value;




  }

  else{

    $overlap = true;

    $tutors = array_unique($tutors, SORT_REGULAR);


    $value->overlap = true;


    $tutors[] = $value;


    break;

  }


  }

                        }


                      }






              }

              else{
                $tutors[]  = $value;


              }

            }

      }


        $tutors = array_unique($tutors, SORT_REGULAR);
        $tutorsWithWarning = array_unique($tutorsWithWarning, SORT_REGULAR);


        foreach($tutors as  $k => $tutor){

          if(in_array($tutor->idx, $tutorsWithWarning)){

              $tutors[$k]->warning = true;
          }
          if(property_exists($tutor, 'overlap') || $tutors[$k]->position === 'Kr_manager'){

             unset($tutors[$k]);

          }
        }




      echo json_encode(array_values($tutors));



    }
  }


  public function checkTeacherSchedule(){


    $start = array();

    $dateWarning = array();

    $end = array();

    $isArray = 'data';

    $overlapStart = array();

    $overlapEnd = array();

    $weekdays = explode(',' , $this->input->post('weekdays'));

    $tutor = json_decode($this->input->post('tutor'));
    $query = $this->tutor->getTutor($tutor->idx);



    if($query){



      $value = $query[0];








    if($value->class_schedule ){



      $checks = json_decode($value->class_schedule);




      foreach($checks as $k => $check){

        if($check->active === false){

          unset($checks[$k]);
          if(count($checks) <=0){

            $checks = null;
          }
        }
      }

      $value->class_schedule = is_array($checks) ? json_encode(array_values($checks)) : $checks;





                   $schedule = json_decode($value->class_schedule);

                    $start_class =  explode(',' , $this->input->post('start_class'));
                    $end_class =   explode(',' , $this->input->post('end_class'));
    foreach($schedule as $value2){

        if($value2->active === true){
      $class_start= explode(',' , json_decode($value2->schedule->class_start))[0] ?  explode(',' , json_decode($value2->schedule->class_start)) : $value2->schedule->class_start;
      $class_end=  explode(',' , json_decode($value2->schedule->class_end))[0] ?  explode(',' , json_decode($value2->schedule->class_end)) :  $value2->schedule->class_end;

          if(is_array($class_start)){




              for($c = 0; $c<count($class_start); $c++){


  for($d =0; $d<count($start_class); $d++){


  if(date(  $start_class[$d]) >= date($class_end[$c]) || date($end_class[$d]) <= date($class_start[$c] )){



    $getStartClass =  explode(" ", date(  $start_class[$d]));
    $getClassStart = explode(" ", date(  $class_start[$c]));
    $getEndClass = explode(" ", date(  $end_class[$d]));
    $getClassEnd = explode(" ", date(  $class_end[$c]));
    $applicableDays = explode(',', json_decode($value2->schedule->applicable_days));




    $diff = array_diff($applicableDays, $weekdays);


    if(count($diff) < count($applicableDays)){
          if(date(  $getStartClass[1]) >= date($getClassEnd[1]) || date($getEndClass[1]) <= date($getClassStart[1])){


          }

          else{


            $dateWarning['start'][] = $start_class[$d];
            $dateWarning['end'][] =  $end_class[$d];

          }

  }







  $start[] = $start_class[$d];
  $end[] =   $end_class[$d];



  }

  else{

$overlapStart[] = $start_class[$d];
    $overlapEnd[] =  $end_class[$d];
  }




  }




  }





}

else{



  $isArray = 'notArray';


    for($d =0; $d<count($start_class); $d++){


    if(date(  $start_class[$d]) >= date($class_end) || date($end_class[$d]) <= date($class_start )){



      $getStartClass =  explode(" ", date(  $start_class[$d]));
      $getClassStart = explode(" ", date(  $class_start));
      $getEndClass = explode(" ", date(  $end_class[$d]));
      $getClassEnd = explode(" ", date(  $class_end));
      $applicableDays = explode(',', json_decode($value2->schedule->applicable_days));




      $diff = array_diff($applicableDays, $weekdays);


      if(count($diff) < count($applicableDays)){
            if(date(  $getStartClass[1]) >= date($getClassEnd[1]) || date($getEndClass[1]) <= date($getClassStart[1])){


            }

            else{


              $dateWarning['start'][] = $start_class[$d];
              $dateWarning['end'][] =  $end_class[$d];

            }

    }







    $start[] = $start_class[$d];
    $end[] =   $end_class[$d];



    }

    else{

  $overlapStart[] = $start_class[$d];
      $overlapEnd[] =  $end_class[$d];
    }




    }








}
}
}
}

  }

  $start = array_unique($start, SORT_REGULAR);
    $end = array_unique($end, SORT_REGULAR);



    foreach($overlapStart as  $k => $startDate){
foreach($start as $d => $startClass){

if($start[$d] === $overlapStart[$k] && $end[$d] === $overlapEnd[$k]){


      unset($start[$d]);
      unset($end[$d]);



    }
    }

  }

    echo json_encode(array('start' => $start, 'end' => $end, 'dateWarning' => $dateWarning, 'data' => $overlapStart));
  }

  public function changeTime(){

    $class_start = json_encode($this->input->post('class_start'));
    $class_end = json_encode($this->input->post('class_end'));
    $tutor = $this->input->post('tutor');
    $classId = $this->input->post('classid');
    $hour = (int)$this->input->post('hour');
    $minute = (int)$this->input->post('minute');
    $dateStart = $this->input->post('dateStart');
    $currentDate = $this->input->post('currentDate');
    $classData = json_decode($this->input->post('classInformation'));

$tutor = $this->tutor->getTutor($tutor)[0];

$classes = [];

$schedules = json_decode($tutor->class_schedule);

if($schedules){

  $classData->type = $schedules[0]->type;
  $classData->active =  false;
  $classData->cancelled =  false;
  $classData->schedule->class_start =   $class_start;
  $classData->schedule->class_end = $class_end;
  $classData->schedule->hour = $hour;
  $classData->schedule->minute = $minute;


  unset($classData->tutor);


  for($i=0; $i<count($schedules); $i++){

    if($schedules[$i]->schedule->classid === $classId && $schedules[$i]->active === false){



        unset($schedules[$i]);





    }
  }





$schedules = array_values($schedules);


  if(date($dateStart) <= date($currentDate)){

    $classData->active = true;


    for($i=0; $i<count($schedules); $i++){


      if($schedules[$i]->schedule->classid === $classId && $schedules[$i]->active === true){



          $schedules[$i]->active = false;




      }
    }


  }
  else{

    $classData->active = false;

  }

  $schedules[] = $classData;





  $newData = array(

    'class_schedule' => json_encode($schedules)

  );


  $success = $this->tutor->updateTutor($tutor->idx, $newData);









}
echo json_encode(array('classes' => $schedules, 'success' => $success));
  }

  public function changeTeacher(){


    if($this->jwt->getToken()){
      $overlap = false;
      $notOverlap = false;
      $tutors = array();
      $tutorsWithWarning = array();
      $test = '';
      $see = array();
      $currentTutor =  $this->input->post('tutor');
      $weekdays = explode(',' , $this->input->post('weekdays'));


      $query = $this->tutor->showAll();

      if($query){

        $result = $this->tutor->showAll();

        for($i =0; $i<count($result); $i++){


        if($result[$i]->class_schedule){

          $checks = json_decode($result[$i]->class_schedule);




          foreach($checks as $k => $check){

            if($check->active === false){

              unset($checks[$k]);
              if(count($checks) <=0){

                $checks = null;
              }
            }
          }

        $result[$i]->class_schedule = is_array($checks) ? json_encode(array_values($checks)) : $checks;

}
        }

        foreach($result as $value){


      if($value->class_schedule){


                  $schedule = json_decode($value->class_schedule);





                      $start_class =  explode(',' , $this->input->post('start_class'));
                      $end_class =   explode(',' , $this->input->post('end_class'));



                      foreach($schedule as $value2){



                        $class_start= explode(',' , json_decode($value2->schedule->class_start))[0] ?  explode(',' , json_decode($value2->schedule->class_start)) : $value2->schedule->class_start;
                        $class_end=  explode(',' , json_decode($value2->schedule->class_end))[0] ?  explode(',' , json_decode($value2->schedule->class_end)) :  $value2->schedule->class_end;

                            if(is_array($class_start)){




                                for($c = 0; $c<count($class_start); $c++){


                for($d =0; $d<count($start_class); $d++){


                  if(date(  $start_class[$d]) >= date($class_end[$c]) || date($end_class[$d]) < date($class_start[$c] )){



                      $getStartClass =  explode(" ", date(  $start_class[$d]));
                      $getClassStart = explode(" ", date(  $class_start[$c]));
                      $getEndClass = explode(" ", date(  $end_class[$d]));
                      $getClassEnd = explode(" ", date(  $class_end[$c]));
                      $applicableDays = explode(',', json_decode($value2->schedule->applicable_days));




                      $diff = array_diff($applicableDays, $weekdays);


                      if(count($diff) < count($applicableDays)){
                            if(date(  $getStartClass[1]) >= date($getClassEnd[1]) || date($getEndClass[1]) < date($getClassStart[1])){


                            }

                            else{


                              $tutorsWithWarning[] = $value->idx;

                            }

}


                 $notOverlap = true;


                 $tutors[] = $value;



             }

             else{



                 $overlap = true;


                 $tutors = array_unique($tutors, SORT_REGULAR);


                 $value->overlap = true;


                 $tutors[] = $value;

                 break;


               }


                }




              }



                        }


                        else{




                            for($d =0; $d<count($start_class); $d++){


                              if(date(  $start_class[$d]) >= date($class_end) || date($end_class[$d]) < date($class_start )){


                                $getStartClass =  explode(" ", date(  $start_class[$d]));
                                $getClassStart = explode(" ", date(  $class_start));
                                $getEndClass = explode(" ", date(  $end_class[$d]));
                                $getClassEnd = explode(" ", date(  $class_end));
                                $applicableDays = explode(',', json_decode($value2->schedule->applicable_days));




                                $diff = array_diff($applicableDays, $weekdays);


                                if(count($diff) < count($applicableDays)){
                                      if(date(  $getStartClass[1]) >= date($getClassEnd[1]) || date($getEndClass[1]) < date($getClassStart[1])){


                                      }

                                      else{


                                        $tutorsWithWarning[] = $value->idx;

                                      }

          }




                             $notOverlap = true;


                                $tutors[] = $value;






                         }

                         else{




                             $overlap = true;
                             $tutors = array_unique($tutors, SORT_REGULAR);






   $value->overlap = true;

   $tutors[] = $value;

   break;


                           }


                            }





                        }








                      }









              }

              else{
                $tutors[]  = $value;


              }

            }


            $tutors = array_unique($tutors, SORT_REGULAR);
            $tutorsWithWarning = array_unique($tutorsWithWarning, SORT_REGULAR);


            foreach($tutors as  $k => $tutor){

              if(in_array($tutor->idx, $tutorsWithWarning)){

                  $tutors[$k]->warning = true;
              }
              if(property_exists($tutor, 'overlap') || $tutors[$k]->position === 'Kr_manager' || $tutors[$k]->idx === $currentTutor){

                 unset($tutors[$k]);

              }
            }




          echo json_encode(array_values($tutors));


      }



    }
  }

  public function changeTeacherSelected(){


    $tutorIdx = $this->input->post('tutoridx');
    $classData = json_decode($this->input->post('classData'));
    $cancelledClass = json_decode($this->input->post('cancelledClass'));

    $selectedTutorIdx = $this->input->post('selectedTutorIdx');

    $tempArray = array();

    $tempArray['type'] = $classData->class_type;
    $tempArray['schedule'] = (array)$classData;
    $tempArray['active'] = true;
    $tempArray['cancelled'] = false;
    $tempArray['cancelled_class'] = $cancelledClass;

    $previousTutor = $this->tutor->getTutor($tutorIdx)[0];
    $currentTutor = $this->tutor->getTutor($selectedTutorIdx)[0];


$previousTutorSchedules = json_decode($previousTutor->class_schedule);
$currentTutorSchedules = json_decode($currentTutor->class_schedule);


for($i =0; $i<count($previousTutorSchedules); $i++){

  if($previousTutorSchedules[$i]->schedule->classid === $classData->classid){

$previousTutorSchedules[$i]->active = false;

  }
}


$previousTutorUpdate = array(

  'class_schedule' => json_encode($previousTutorSchedules)
);




$currentTutorSchedules[] = $tempArray;

$currentTutorUpdate = array(

  'class_schedule' => json_encode($currentTutorSchedules)
);

$success1 = $this->tutor->updateTutor($tutorIdx, $previousTutorUpdate);

  $success2 = $this->tutor->updateTutor($selectedTutorIdx, $currentTutorUpdate);

    echo json_encode(array('success1' => $success1, 'success2' => $success2));
  }

  public function changeTeachernTimeAvailable(){

    if($this->jwt->getToken()){
      $overlap = false;
      $notOverlap = false;
      $tutors = array();



      $tutorsWithWarning = array();







      $start_class = $this->input->post('start_class');
      $end_class = $this->input->post('end_class');



      $weekdays = explode(',' , $this->input->post('weekdays'));


      $query = $this->tutor->showAll();

      if($query){

        $result = $this->tutor->showAll();

        for($i =0; $i<count($result); $i++){


        if($result[$i]->class_schedule){

          $checks = json_decode($result[$i]->class_schedule);




          foreach($checks as $k => $check){

            if($check->active === false){

              unset($checks[$k]);
              if(count($checks) <=0){

                $checks = null;
              }
            }
          }

        $result[$i]->class_schedule = is_array($checks) ? json_encode(array_values($checks)) : $checks;

}
        }



        foreach($result as $value){


      if($value->class_schedule){


                  $schedule = json_decode($value->class_schedule);





                      $start_class =  explode(',' , $this->input->post('start_class'));
                      $end_class =   explode(',' , $this->input->post('end_class'));



                      foreach($schedule as $value2){



                        $class_start= explode(',' , json_decode($value2->schedule->class_start))[0] ?  explode(',' , json_decode($value2->schedule->class_start)) : $value2->schedule->class_start;
                        $class_end=  explode(',' , json_decode($value2->schedule->class_end))[0] ?  explode(',' , json_decode($value2->schedule->class_end)) :  $value2->schedule->class_end;

                            if(is_array($class_start)){




                                for($c = 0; $c<count($class_start); $c++){


                for($d =0; $d<count($start_class); $d++){


                  if(date(  $start_class[$d]) >= date($class_end[$c]) || date($end_class[$d]) < date($class_start[$c] )){



                      $getStartClass =  explode(" ", date(  $start_class[$d]));
                      $getClassStart = explode(" ", date(  $class_start[$c]));
                      $getEndClass = explode(" ", date(  $end_class[$d]));
                      $getClassEnd = explode(" ", date(  $class_end[$c]));
                      $applicableDays = explode(',', json_decode($value2->schedule->applicable_days));




                      $diff = array_diff($applicableDays, $weekdays);


                      if(count($diff) < count($applicableDays)){
                            if(date(  $getStartClass[1]) >= date($getClassEnd[1]) || date($getEndClass[1]) < date($getClassStart[1])){


                            }

                            else{


                              $tutorsWithWarning[] = $value->idx;

                            }

}


                 $notOverlap = true;


                 $tutors[] = $value;



             }

             else{



                 $overlap = true;


                 $tutors = array_unique($tutors, SORT_REGULAR);


                 $value->overlap = true;


                 $tutors[] = $value;

                 break;


               }


                }




              }



                        }


                        else{




                            for($d =0; $d<count($start_class); $d++){


                              if(date(  $start_class[$d]) >= date($class_end) || date($end_class[$d]) < date($class_start )){


                                $getStartClass =  explode(" ", date(  $start_class[$d]));
                                $getClassStart = explode(" ", date(  $class_start));
                                $getEndClass = explode(" ", date(  $end_class[$d]));
                                $getClassEnd = explode(" ", date(  $class_end));
                                $applicableDays = explode(',', json_decode($value2->schedule->applicable_days));




                                $diff = array_diff($applicableDays, $weekdays);


                                if(count($diff) < count($applicableDays)){
                                      if(date(  $getStartClass[1]) >= date($getClassEnd[1]) || date($getEndClass[1]) < date($getClassStart[1])){


                                      }

                                      else{


                                        $tutorsWithWarning[] = $value->idx;

                                      }

          }




                             $notOverlap = true;


                                $tutors[] = $value;






                         }

                         else{




                             $overlap = true;
                             $tutors = array_unique($tutors, SORT_REGULAR);






   $value->overlap = true;

   $tutors[] = $value;

   break;


                           }


                            }





                        }








                      }









              }

              else{
                $tutors[]  = $value;


              }

            }

      }


        $tutors = array_unique($tutors, SORT_REGULAR);
        $tutorsWithWarning = array_unique($tutorsWithWarning, SORT_REGULAR);


        foreach($tutors as  $k => $tutor){

          if(in_array($tutor->idx, $tutorsWithWarning)){

              $tutors[$k]->warning = true;
          }
          if(property_exists($tutor, 'overlap') || $tutors[$k]->position === 'Kr_manager'){

             unset($tutors[$k]);

          }
        }




      echo json_encode(array_values($tutors));



    }
  }

  public function changeTeachernTimeSelected(){

    $tutorIdx = $this->input->post('tutoridx');
    $classData = json_decode($this->input->post('classData'));
    $cancelledClass = json_decode($this->input->post('cancelledClass'));

    $classData->class_start = json_encode($classData->class_start);
    $classData->class_end = json_encode($classData->class_end);

    $selectedTutorIdx = $this->input->post('selectedTutorIdx');

    $tempArray = array();

    $tempArray['type'] = $classData->class_type;
    $tempArray['schedule'] = (array)$classData;
    $tempArray['active'] = true;
    $tempArray['cancelled'] = false;
    $tempArray['cancelled_class'] = $cancelledClass;

    $previousTutor = $this->tutor->getTutor($tutorIdx)[0];
    $currentTutor = $this->tutor->getTutor($selectedTutorIdx)[0];


$previousTutorSchedules = json_decode($previousTutor->class_schedule);
$currentTutorSchedules = json_decode($currentTutor->class_schedule);


for($i =0; $i<count($previousTutorSchedules); $i++){

  if($previousTutorSchedules[$i]->schedule->classid === $classData->classid){

$previousTutorSchedules[$i]->active = false;

  }
}


$previousTutorUpdate = array(

  'class_schedule' => json_encode($previousTutorSchedules)
);




$currentTutorSchedules[] = $tempArray;

$currentTutorUpdate = array(

  'class_schedule' => json_encode($currentTutorSchedules)
);

$success1 = $this->tutor->updateTutor($tutorIdx, $previousTutorUpdate);

  $success2 = $this->tutor->updateTutor($selectedTutorIdx, $currentTutorUpdate);

    echo json_encode(array('success1' => $success1, 'success2' => $success2));

  }

  public function getMakeUpClassAvailableTutors(){
    if($this->jwt->getToken()){

      $overlap = false;
      $notOverlap = false;
      $tutors = array();



      $tutorsWithWarning = array();



      $start_class = $this->input->post('start_class');
      $end_class = $this->input->post('end_class');

      $weekdays = explode(',' , $this->input->post('weekdays'));

      $query = $this->tutor->showAll();

      if($query){

        $result = $this->tutor->showAll();

        for($i =0; $i<count($result); $i++){


        if($result[$i]->class_schedule){

          $checks = json_decode($result[$i]->class_schedule);




          foreach($checks as $k => $check){

            if($check->active === false){

              unset($checks[$k]);
              if(count($checks) <=0){

                $checks = null;
              }
            }
          }

        $result[$i]->class_schedule = is_array($checks) ? json_encode(array_values($checks)) : $checks;

}
        }



        foreach($result as $value){


      if($value->class_schedule){


                  $schedule = json_decode($value->class_schedule);






                        foreach($schedule  as $value2){




                          $class_start= explode(',' , json_decode($value2->schedule->class_start))[0] ?  explode(',' , json_decode($value2->schedule->class_start)) : $value2->schedule->class_start;
                          $class_end=  explode(',' , json_decode($value2->schedule->class_end))[0] ?  explode(',' , json_decode($value2->schedule->class_end)) :  $value2->schedule->class_end;

                          if(is_array($class_start)){


                          foreach($class_start as $key => $class){



                            if(date($start_class) >= date($class_end[$key]) || date($end_class) < date($class )){


                              $getStartClass =  explode(" ", date($start_class));
                              $getClassStart = explode(" ", date($class));
                              $getEndClass = explode(" ", date($end_class));
                              $getClassEnd = explode(" ", date($class_end[$key]));
                              $applicableDays = explode(',', json_decode($value2->schedule->applicable_days));




                              $diff = array_diff($applicableDays, $weekdays);


                              if(count($diff) < count($applicableDays)){
                                    if(date(  $getStartClass[1]) >= date($getClassEnd[1]) || date($getEndClass[1]) < date($getClassStart[1])){


                                    }

                                    else{


                                      $tutorsWithWarning[] = $value->idx;

                                    }

                    }
                              $notOverlap = true;

                                $tutors[] = $value;

                          }

                          else{

                            $overlap = true;

                            $tutors = array_unique($tutors, SORT_REGULAR);


                        $value->overlap = true;

                        $tutors[] = $value;

                        break;



                          }






                        }

  }

  else{

    if(date($start_class) >= date($class_end) || date($end_class) < date($class_start)){



      $getStartClass =  explode(" ", date( $start_class));
      $getClassStart = explode(" ", date( $class_start));
      $getEndClass = explode(" ", date( $end_class));
      $getClassEnd = explode(" ", date( $class_end));
      $applicableDays = explode(',', json_decode($value2->schedule->applicable_days));




      $diff = array_diff($applicableDays, $weekdays);


      if(count($diff) < count($applicableDays)){
            if(date(  $getStartClass[1]) >= date($getClassEnd[1]) || date($getEndClass[1]) < date($getClassStart[1])){


            }

            else{


              $tutorsWithWarning[] = $value->idx;

            }

    }

      $notOverlap = true;

        $tutors[] = $value;




  }

  else{

    $overlap = true;

    $tutors = array_unique($tutors, SORT_REGULAR);


    $value->overlap = true;


    $tutors[] = $value;


    break;

  }


  }

                        }









              }

              else{
                $tutors[]  = $value;


              }

            }

      }



              $tutors = array_unique($tutors, SORT_REGULAR);
              $tutorsWithWarning = array_unique($tutorsWithWarning, SORT_REGULAR);


              foreach($tutors as  $k => $tutor){

                if(in_array($tutor->idx, $tutorsWithWarning)){

                    $tutors[$k]->warning = true;
                }
                if(property_exists($tutor, 'overlap') || $tutors[$k]->position === 'Kr_manager'){

                   unset($tutors[$k]);

                }
              }




            echo json_encode(array_values($tutors));

  }

  }


  public function setMakeUpClass(){
      if($this->jwt->getToken()){
    $cancelDateStart = $this->input->post('cancelDateStart');
    $cancelDateEnd = $this->input->post('cancelDateEnd');
    $makeUpDate = $this->input->post('makeUpDate');
    $start_class = $this->input->post('start_class');
    $end_class = $this->input->post('end_class');
    $tutorIdx = $this->input->post('tutorIdx');
    $selectedTutorIdx = $this->input->post('selectedTutorIdx');
    $hour = (int)$this->input->post('hour');
    $minute = (int)$this->input->post('minute');
    $classId = $this->input->post('classid');
    $classData = json_decode($this->input->post('classData'));
    unset($classData->tutor);

    $tempArray = array();
    $classData->schedule->hour = $hour;
    $classData->schedule->minute = $minute;
    $classData->schedule->class_start = $start_class;
    $classData->schedule->class_end = $end_class;
    $classData->schedule->makeUpDate = $makeUpDate;


    $tempArray['type'] = $classData->schedule->class_type;
    $tempArray['schedule'] = (array)$classData->schedule;
    $tempArray['active'] = true;
    $tempArray['cancelled'] = true;
    $tempArray['cancelled_class'] = array();


    $currentTutor = $this->tutor->getTutor($tutorIdx)[0];
    $selectedTutor = $this->tutor->getTutor($selectedTutorIdx)[0];

    $currentTutorSchedules = json_decode($currentTutor->class_schedule);
    $selectedTutorSchedules = json_decode($selectedTutor->class_schedule);
    $selectedTutorSchedules[] = $tempArray;


      if($currentTutorSchedules){


        foreach($currentTutorSchedules as $k => $schedule){

          if($schedule->schedule->classid === $classId && $schedule->active === true){

            $class_start= explode(',' , json_decode($schedule->schedule->class_start));

          array_splice( $class_start, count($class_start)-1, 0, $start_class);
            $class_end=  explode(',' , json_decode($schedule->schedule->class_end));

            array_splice( $class_end, count($class_end)-1, 0, $end_class);


$currentTutorSchedules[$k]->schedule->class_start =  json_encode( implode(',' , $class_start));
$currentTutorSchedules[$k]->schedule->class_end =  json_encode( implode(',', $class_end));




if(property_exists($currentTutorSchedules[$k], 'cancelled_class')){

  $currentTutorSchedules[$k]->cancelled_class[] = $cancelDateStart;
  $currentTutorSchedules[$k]->cancelled_class[] = $cancelDateEnd;
}

else{

$currentTutorSchedules[$k]->cancelled_class = array();
$currentTutorSchedules[$k]->cancelled_class[] = $cancelDateStart;
$currentTutorSchedules[$k]->cancelled_class[] = $cancelDateEnd;
}



          }


        }
      }

      $previousTutorUpdate = array(

        'class_schedule' => json_encode(  $currentTutorSchedules)
      );


      $selectedTutorUpdate = array(

        'class_schedule' => json_encode(  $selectedTutorSchedules)
      );


      $success1 = $this->tutor->updateTutor($tutorIdx, $previousTutorUpdate);

        $success2 = $this->tutor->updateTutor($selectedTutorIdx, $selectedTutorUpdate);

          echo json_encode(array('success1' => $success1, 'success2' => $success2));








}

  }


  public function getStudent(){

    $classId = $this->input->post('classId');

$evaluation = '';


    if($this->jwt->getToken()){



    $user = $this->jwt->getToken();

    $tutor =   $this->tutor->getTutor($user[0]->idx)[0];

      $schedules = json_decode($tutor->class_schedule);

      foreach($schedules as $k => $value){

        if($value->schedule->classid === $classId){

          $class =  $value;
        }

      }

        $evaluation = $this->evaluation->getEvaluation($classId) ? $this->evaluation->getEvaluation($classId)[0] : '';
        if($evaluation){
        $evaluation->evaluation = json_decode($evaluation->evaluation);
      }
      if($class && $tutor){

    echo json_encode(['class' => $class, 'tutor' => $tutor, 'evaluation' => $evaluation]);

  }

  }
  }



  public function getRegularStudent(){

    $classId = $this->input->post('classId');

$evaluation = '';


    if($this->jwt->getToken()){



    $user = $this->jwt->getToken();

    $tutor =   $this->tutor->getTutor($user[0]->idx)[0];



      $schedules = json_decode($tutor->class_schedule);
if($schedules){
      foreach($schedules as $k => $value){

        if($value->schedule->classid === $classId){

          $class =  $value;
        }

      }

        $evaluation = $this->evaluation->getEvaluation($classId) ?  $this->evaluation->getEvaluation($classId)[0]: '';
        if($evaluation){
        $evaluation->evaluation = json_decode($evaluation->evaluation);
      }

      else{

          $evaluation = $this->evaluation->getleveltestEvaluation($class->schedule->preference_number) ? $this->evaluation->getleveltestEvaluation($class->schedule->preference_number)[0] : '';

          if($evaluation){

              $evaluation->evaluation = json_decode($evaluation->evaluation);
          }
      }
      if($class && $tutor){

    echo json_encode(['class' => $class, 'tutor' => $tutor, 'evaluation' => $evaluation]);

  }
}
  }
  }

  public function saveLevel(){

    if($this->jwt->getToken()){



    $user = $this->jwt->getToken();

    $tutor =   $this->tutor->getTutor($user[0]->idx)[0];
      $classid = $this->input->post('classid');
      $Level = $this->input->post('Level');

      $schedules = json_decode($tutor->class_schedule);
if($schedules){
      foreach($schedules as $k => $value){

        if($value->schedule->classid === $classid){

          $schedules[$k]->schedule->level = $Level;

        }

      }

      $newArray = array(

        'class_schedule' => json_encode($schedules)
      );


      if($this->tutor->updateTutor($tutor->idx, $newArray)){

    echo json_encode('Level updated Successfully');

  }
    }



    }
  }


  public function SaveCurriculum(){



      if($this->jwt->getToken()){



      $user = $this->jwt->getToken();

      $tutor =   $this->tutor->getTutor($user[0]->idx)[0];
        $classid = $this->input->post('classid');
        $curriculum = $this->input->post('Curriculum');
        $material = $this->input->post('Material');

        $schedules = json_decode($tutor->class_schedule);
  if($schedules){
        foreach($schedules as $k => $value){

          if($value->schedule->classid === $classid){

            $schedules[$k]->schedule->curriculum = $curriculum;

            $schedules[$k]->schedule->bookMaterial = $material;
          }

        }

        $newArray = array(

          'class_schedule' => json_encode($schedules)
        );


        if($this->tutor->updateTutor($tutor->idx, $newArray)){

      echo json_encode('Level updated Successfully');

    }
      }



      }

  }





  public function changeOutgoingSchedule(){

    if($this->jwt->getToken()){
        $tutorIdx = $this->input->post('tutoridx');
        $classData = json_decode($this->input->post('classData'));

        $classData->class_start = date($classData->class_start);
        $classData->class_end = date($classData->class_end);

        $selectedTutorIdx = $this->input->post('selectedTutorIdx');

        unset($classData->tutor_idx);
        unset($classData->tutor_name);

        $tempArray = array();

        $tempArray['type'] = $classData->class_type;
        $tempArray['schedule'] = (array)$classData;
        $tempArray['active'] = true;
        $tempArray['cancelled'] = false;
        $tempArray['cancelled_class'] = array();

        $previousTutor = $this->tutor->getTutor($tutorIdx)[0];
        $currentTutor = $this->tutor->getTutor($selectedTutorIdx)[0];


    $previousTutorSchedules = json_decode($previousTutor->class_schedule);
    $currentTutorSchedules = json_decode($currentTutor->class_schedule);


    for($i =0; $i<count($previousTutorSchedules); $i++){

      if($previousTutorSchedules[$i]->schedule->classid === $classData->classid){

        if($tutorIdx ===  $selectedTutorIdx){

          $currentTutorSchedules[$i]->active = false;
        }

    $previousTutorSchedules[$i]->active = false;

      }
    }


    $previousTutorUpdate = array(

      'class_schedule' => json_encode($previousTutorSchedules)
    );




    $currentTutorSchedules[] = $tempArray;

    $currentTutorUpdate = array(

      'class_schedule' => json_encode($currentTutorSchedules)
    );

    $success1 = $this->tutor->updateTutor($tutorIdx, $previousTutorUpdate);

      $success2 = $this->tutor->updateTutor($selectedTutorIdx, $currentTutorUpdate);

        echo json_encode(array('success1' => $success1, 'success2' => $success2));

  }

}


public function outGoingTeacherAvailable(){

  if($this->jwt->getToken()){
    $overlap = false;
    $notOverlap = false;
    $tutors = array();

    $type = false;

    $tutorsWithWarning = array();







    $start_class = $this->input->post('start_class');
    $end_class = $this->input->post('end_class');



    $weekdays = explode(',' , $this->input->post('weekdays'));


    $query = $this->tutor->showAll();

    if($query){

      $result = $this->tutor->showAll();

      for($i =0; $i<count($result); $i++){


      if($result[$i]->class_schedule){

        $checks = json_decode($result[$i]->class_schedule);




        foreach($checks as $k => $check){

          if($check->active === false){

            unset($checks[$k]);
            if(count($checks) <=0){

              $checks = null;
            }
          }
        }

      $result[$i]->class_schedule = is_array($checks) ? json_encode(array_values($checks)) : $checks;

  }
      }



      foreach($result as $value){


    if($value->class_schedule){


                $schedule = json_decode($value->class_schedule);




                      foreach($schedule  as $value2){




                          $class_start= explode(',' , json_decode($value2->schedule->class_start))[0] ?  explode(',' , json_decode($value2->schedule->class_start)) : $value2->schedule->class_start;
                        $class_end=  explode(',' , json_decode($value2->schedule->class_end))[0] ?  explode(',' , json_decode($value2->schedule->class_end)) :  $value2->schedule->class_end;

                        if(is_array($class_start)){


                        foreach($class_start as $key => $class){



                          if(date($start_class) >= date($class_end[$key]) || date($end_class) < date($class )){


                            $getStartClass =  explode(" ", date($start_class));
                            $getClassStart = explode(" ", date($class));
                            $getEndClass = explode(" ", date($end_class));
                            $getClassEnd = explode(" ", date($class_end[$key]));
                            $applicableDays = explode(',', json_decode($value2->schedule->applicable_days));




                            $diff = array_diff($applicableDays, $weekdays);


                            if(count($diff) < count($applicableDays)){
                                  if(date(  $getStartClass[1]) >= date($getClassEnd[1]) || date($getEndClass[1]) < date($getClassStart[1])){


                                  }

                                  else{


                                    $tutorsWithWarning[] = $value->idx;

                                  }

                  }
                            $notOverlap = true;

                              $tutors[] = $value;

                        }

                        else{

                          $overlap = true;

                          $tutors = array_unique($tutors, SORT_REGULAR);


                      $value->overlap = true;

                      $tutors[] = $value;

                      break;



                        }






                      }

  }

  else{

  if(date($start_class) >= date($class_end) || date($end_class) < date($class_start)){



    $getStartClass =  explode(" ", date( $start_class));
    $getClassStart = explode(" ", date( $class_start));
    $getEndClass = explode(" ", date( $end_class));
    $getClassEnd = explode(" ", date( $class_end));
    $applicableDays = explode(',', json_decode($value2->schedule->applicable_days));




    $diff = array_diff($applicableDays, $weekdays);


    if(count($diff) < count($applicableDays)){
          if(date(  $getStartClass[1]) >= date($getClassEnd[1]) || date($getEndClass[1]) < date($getClassStart[1])){


          }

          else{


            $tutorsWithWarning[] = $value->idx;

          }

  }

    $notOverlap = true;

      $tutors[] = $value;




  }

  else{

  $overlap = true;

  $tutors = array_unique($tutors, SORT_REGULAR);


  $value->overlap = true;


  $tutors[] = $value;


  break;

  }


  }

                      }









            }

            else{
              $tutors[]  = $value;


            }

          }

    }


      $tutors = array_unique($tutors, SORT_REGULAR);
      $tutorsWithWarning = array_unique($tutorsWithWarning, SORT_REGULAR);


      foreach($tutors as  $k => $tutor){

        if(in_array($tutor->idx, $tutorsWithWarning)){

            $tutors[$k]->warning = true;
        }
        if(property_exists($tutor, 'overlap') || $tutors[$k]->position === 'Kr_manager'){

           unset($tutors[$k]);

        }
      }




    echo json_encode(array_values($tutors));



  }


}

public function outGoingTeacherSelected(){

  if($this->jwt->getToken()){

    $tutorIdx = $this->input->post('tutoridx');
    $classData = json_decode($this->input->post('classData'));


    $selectedTutorIdx = $this->input->post('selectedTutorIdx');

    $tempArray = array();

    unset($classData->tutor_idx);
    unset($classData->tutor_name);

    $tempArray['type'] = $classData->class_type;
    $tempArray['schedule'] = (array)$classData;
    $tempArray['active'] = true;
    $tempArray['cancelled'] = false;
    $tempArray['cancelled_class'] = array();

    $previousTutor = $this->tutor->getTutor($tutorIdx)[0];
    $currentTutor = $this->tutor->getTutor($selectedTutorIdx)[0];


$previousTutorSchedules = json_decode($previousTutor->class_schedule);
$currentTutorSchedules = json_decode($currentTutor->class_schedule);


for($i =0; $i<count($previousTutorSchedules); $i++){

  if($previousTutorSchedules[$i]->schedule->classid === $classData->classid){

$previousTutorSchedules[$i]->active = false;

  }
}


$previousTutorUpdate = array(

  'class_schedule' => json_encode($previousTutorSchedules)
);




$currentTutorSchedules[] = $tempArray;

$currentTutorUpdate = array(

  'class_schedule' => json_encode($currentTutorSchedules)
);

$success1 = $this->tutor->updateTutor($tutorIdx, $previousTutorUpdate);

  $success2 = $this->tutor->updateTutor($selectedTutorIdx, $currentTutorUpdate);

    echo json_encode(array('success1' => $success1, 'success2' => $success2));

  }

}


public function getTeamMembers(){

  if($this->jwt->getToken()){

    $user = $this->jwt->getToken();

    $tutor =   $this->tutor->getTutor($user[0]->idx)[0];

    $getAllTutors = $this->tutor->showAll();

  if($tutor->position === 'Team_leader' || $tutor->position === 'Assistant_team_leader' && $tutor->status === 'active' ){
      $team = $tutor->team;

      if($team){
      $teamMembers = $this->tutor->get_team_members($team);
      $teamMonitoring = $this->tutor->get_team_members_monitoring($team);
    }



      if($teamMembers){

        echo  json_encode(array('teamMembers' => $teamMembers, 'teamMonitoring' => $teamMonitoring, 'Tutors' => $getAllTutors, 'teamLeader' => $tutor));
      }

  }

}

}

public function getClassLists(){
  if($this->jwt->getToken()){

    $selectedMember = $this->input->post('selectedMember');



    $tutor =   $this->tutor->getTutor($selectedMember)[0];

  $hourRange = explode("," , $this->input->post('hourRange'));
  $selectedDate = $this->input->post('selectedDate');

  $classes = array();

  $schedules = json_decode($tutor->class_schedule);

if($schedules){
    foreach($schedules as $schedule){
                  if($schedule->active === true){
              $class_start = explode(',' , json_decode($schedule->schedule->class_start))[0] ?   explode(',' , json_decode($schedule->schedule->class_start)) : $schedule->schedule->class_start;
              $class_end = explode(',' , json_decode($schedule->schedule->class_end))[0] ?   explode(',' , json_decode($schedule->schedule->class_end)) : $schedule->schedule->class_end;
              if(is_array($class_start)){

              foreach ($class_start as $c => $value) {

                $classStart = explode(" ", $value);


                 if(in_array($schedule->schedule->hour, $hourRange) && date($selectedDate) === date($classStart[0]) ){

                        $tempArray = array(

                          'class_start' => $value,
                          'class_end' => $class_end[$c],
                          'classid' => $schedule->schedule->classid,
                          'hour' => $schedule->schedule->hour,
                          'duration' => $schedule->schedule->duration,
                          'minute' =>  $schedule->schedule->minute,
                          'name' => $schedule->schedule->name,
                          'account' => $schedule->schedule->academy,
                          'material' => $schedule->schedule->bookMaterial,
                          'schedule' =>  $schedule->schedule


                        );
                        $classes[] = $tempArray;

                    }

              }

              }


              else{

                $classStart = explode(" ", $class_start);


                 if(in_array($schedule->schedule->hour, $hourRange) && date($selectedDate) === date($classStart[0]) ){

                    $tempArray = array(

                      'class_start' => $class_start,
                      'class_end' => $schedule->schedule->class_end,
                      'classid' => $schedule->schedule->classid,
                      'hour' => $schedule->schedule->hour,
                      'duration' => $schedule->schedule->duration,
                      'minute' =>  $schedule->schedule->minute,
                      'name' => $schedule->schedule->name,
                      'account' => $schedule->schedule->academy,
                      'schedule' =>  $schedule->schedule

                    );
                    $classes[] = $tempArray;

                  }
              }
    }
}

  }

if($classes){



  echo json_encode(array('classes' =>  $classes, 'success' => true));
}

else{

    echo json_encode(array( 'success' => false));
}

}
}


public function get_take_over_available(){

  if($this->jwt->getToken()){
    $overlap = false;
    $notOverlap = false;
    $tutors = array();



    $tutorsWithWarning = array();







    $start_class = $this->input->post('start_class');
    $end_class = $this->input->post('end_class');
    $weekdays = explode(',' , $this->input->post('weekdays'));






    $query = $this->tutor->showAll();

    if($query){

      $result = $this->tutor->showAll();

      for($i =0; $i<count($result); $i++){


      if($result[$i]->class_schedule){

        $checks = json_decode($result[$i]->class_schedule);




        foreach($checks as $k => $check){

          if($check->active === false){

            unset($checks[$k]);
            if(count($checks) <=0){

              $checks = null;
            }
          }
        }

      $result[$i]->class_schedule = is_array($checks) ? json_encode(array_values($checks)) : $checks;

}
      }



      foreach($result as $value){


    if($value->class_schedule){


                $schedule = json_decode($value->class_schedule);







                  $test = array();

                      foreach($schedule  as $value2){






                        $class_start= explode(',' , json_decode($value2->schedule->class_start))[0] ?  explode(',' , json_decode($value2->schedule->class_start)) : $value2->schedule->class_start;
                      $class_end=  explode(',' , json_decode($value2->schedule->class_end))[0] ?  explode(',' , json_decode($value2->schedule->class_end)) :  $value2->schedule->class_end;

                      if(is_array($class_start)){



                        foreach($class_start as $key => $class){



                          if(date($start_class) >= date($class_end[$key]) || date($end_class) < date($class )){


                            $getStartClass =  explode(" ", date($start_class));
                            $getClassStart = explode(" ", date($class));
                            $getEndClass = explode(" ", date($end_class));
                            $getClassEnd = explode(" ", date($class_end[$key]));
                            $applicableDays = explode(',', json_decode($value2->schedule->applicable_days));




                            $diff = array_diff($applicableDays, $weekdays);


                            if(count($diff) < count($applicableDays)){
                                  if(date(  $getStartClass[1]) >= date($getClassEnd[1]) || date($getEndClass[1]) < date($getClassStart[1])){


                                  }

                                  else{


                                    $tutorsWithWarning[] = $value->idx;

                                  }

                  }
                            $notOverlap = true;

                              $tutors[] = $value;

                        }

                        else{

                          $overlap = true;

                          $tutors = array_unique($tutors, SORT_REGULAR);


                      $value->overlap = true;

                      $tutors[] = $value;

                      break;



                        }






                      }

}

else{

  if(date($start_class) >= date($class_end) || date($end_class) < date($class_start)){



    $getStartClass =  explode(" ", date( $start_class));
    $getClassStart = explode(" ", date( $class_start));
    $getEndClass = explode(" ", date( $end_class));
    $getClassEnd = explode(" ", date( $class_end));
    $applicableDays = explode(',', json_decode($value2->schedule->applicable_days));




    $diff = array_diff($applicableDays, $weekdays);


    if(count($diff) < count($applicableDays)){
          if(date(  $getStartClass[1]) >= date($getClassEnd[1]) || date($getEndClass[1]) < date($getClassStart[1])){


          }

          else{


            $tutorsWithWarning[] = $value->idx;

          }

  }

    $notOverlap = true;

      $tutors[] = $value;




}

else{

  $overlap = true;

  $tutors = array_unique($tutors, SORT_REGULAR);


  $value->overlap = true;


  $tutors[] = $value;


  break;

}


}

                      }









            }

            else{
              $tutors[]  = $value;


            }

          }

    }


      $tutors = array_unique($tutors, SORT_REGULAR);
      $tutorsWithWarning = array_unique($tutorsWithWarning, SORT_REGULAR);


      foreach($tutors as  $k => $tutor){

        if(in_array($tutor->idx, $tutorsWithWarning)){

            $tutors[$k]->warning = true;
        }
        if(property_exists($tutor, 'overlap') || $tutors[$k]->position === 'Kr_manager'){

           unset($tutors[$k]);

        }
      }




      echo json_encode(array_values($tutors));



  }
}

public function set_take_over(){

    if($this->jwt->getToken()){

      $selectedClasses = array_values(json_decode($this->input->post('selectedClasses')));



      if($selectedClasses){

        foreach ($selectedClasses as $key => $class) {
          $currentTutor = $class->currentTutor;
          $selectedTutor = $class->selectedTutor;
          $schedule = $class->schedule;
          $schedule->applicable_days = json_encode($schedule->applicable_days);


          $selectedTutor = $this->tutor->getTutor($selectedTutor)[0];

          $selectedTutorSchedules = json_decode($selectedTutor->class_schedule);

          $tempArray = array();

          $tempArray['TO'] = true;
          $tempArray['schedule'] = (array)$schedule;
          $tempArray['active']  = true;
          $tempArray['type'] = $schedule->class_type;


          $selectedTutorSchedules[] = $tempArray;

          $newArray = array(

            'class_schedule' => json_encode($selectedTutorSchedules)
          );

          $success = $this->tutor->updateTutor($selectedTutor->idx, $newArray);
        }

        echo json_encode(array('success' => $success));
      }
    }
}

public function saveMonitoring(){

    if($this->jwt->getToken()){
  $selectedTutor = $this->input->post('selectedTutor');

  $tutor = $this->tutor->getTutor($selectedTutor)[0];

    $teamLeader = $this->jwt->getToken()[0];
  $updatedData = array(

    'team_monitoring' =>  $teamLeader->team
  );

  $success = $this->tutor->updateTutor($selectedTutor, $updatedData);

echo json_encode(array('success' => $success));
}
}

public function get_all_classes_by_tutor(){

  if($this->jwt->getToken()){

    $tutorIdx = $this->input->post('memberIdx');

    $tutor = $this->tutor->getTutor($tutorIdx)[0];

    $tutorSchedules = json_decode($tutor->class_schedule);

    $tutorClasses = array();

    if($tutorSchedules){

      foreach ($tutorSchedules as $key => $schedule) {
          if($schedule->active === true){

            $tutorClasses[] = $schedule;
          }
      }

      echo json_encode(array('tutor' => $tutor, 'tutorClasses' => $tutorClasses ));
    }
  }
}

public function cancel_take_over_selected(){

  if($this->jwt->getToken()){

    $tutorIdx = $this->input->post('tutoridx');
    $classData = json_decode($this->input->post('classData'));


    $selectedTutorIdx = $this->input->post('selectedTutorIdx');

    $tempArray = array();


    $tempArray['TO'] = true;
    $tempArray['type'] = $classData->class_type;
    $tempArray['schedule'] = (array)$classData;
    $tempArray['active'] = true;


    $previousTutor = $this->tutor->getTutor($tutorIdx)[0];
    $currentTutor = $this->tutor->getTutor($selectedTutorIdx)[0];


$previousTutorSchedules = json_decode($previousTutor->class_schedule);
$currentTutorSchedules = json_decode($currentTutor->class_schedule);


for($i =0; $i<count($previousTutorSchedules); $i++){

  if($previousTutorSchedules[$i]->schedule->classid === $classData->classid){

$previousTutorSchedules[$i]->active = false;

  }
}


$previousTutorUpdate = array(

  'class_schedule' => json_encode($previousTutorSchedules)
);




$currentTutorSchedules[] = $tempArray;

$currentTutorUpdate = array(

  'class_schedule' => json_encode($currentTutorSchedules)
);

$success1 = $this->tutor->updateTutor($tutorIdx, $previousTutorUpdate);

  $success2 = $this->tutor->updateTutor($selectedTutorIdx, $currentTutorUpdate);

    echo json_encode(array('success1' => $success1, 'success2' => $success2));

  }
}


public function get_ph_tutors(){

  if($this->jwt->getToken()){

    $user = $this->jwt->getToken();

    $tutor =   $this->tutor->getTutor($user[0]->idx)[0];

    $getAllTutors = $this->tutor->showAll();

  if($tutor->position !== 'Tutor' || $tutor->position !== 'Trainee' && $tutor->status === 'active' ){



    echo json_encode(array('Tutors' => $getAllTutors));


  }

}
}

public function check_zoom_room(){

$meetingId = (int)$this->input->post('meetingId');
$meetingPw =  (int)$this->input->post('meetingPw');
$classId = $this->input->post('classId');

if($meetingId && $meetingPw && $this->jwt->getToken()){


$user  = $this->jwt->getToken()[0];

$getUser = $this->tutor->getTutor($user->idx)[0];

if($getUser){


  $schedules = json_decode($getUser->class_schedule);

  if($schedules){

    foreach ($schedules as $key => $value) {

      if($value->schedule->classid === $classId && $value->active === true){

      $schedules[$key]->schedule->meetingId = $meetingId;
      $schedules[$key]->schedule->meetingPw = $meetingPw;

    }
    }

    $newData = array(

      'class_schedule' => json_encode($schedules)
    );

  $success =   $this->tutor->updateTutor($getUser->idx, $newData);

  echo json_encode(array('success' => $success));
  }


}




}

}













}
