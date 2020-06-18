<?php

defined('BASEPATH') OR exit('No direct script access allowed');
class Leveltest extends CI_Controller {

  function __construct(){

    parent::__construct();

    $this->load->model('leveltest_model', 'leveltest');
    $this->load->model('tutor_model', 'tutor');
  }


  function connid_key() {
          $this->load->library('uuid');
          $id = $this->uuid->v4();
          return $id;
  }

  function uuid_key() {
          $this->load->library('uuid');
          //Output a v4 UUID
          $id = $this->uuid->v4();
          $id = str_replace('-', '', $id);
          $id = substr($id, 24);
          return $id;
  }

  public function index(){


    $this->load->view('welcome_message');
  }


  public function showAll(){

    $query = $this->leveltest->showAll();

    if($query){

      $result['leveltest'] = $this->leveltest->showAll();
    }

    echo json_encode($result);
  }




  public function addLevelTest(){

    $config = array(

    array(
      'field' => 'name',
      'label' => 'Name',
      'rules' => 'trim|required'
    ),

    array(
      'field' => 'kr_name',
      'label' => 'KoreanName',
      'rules' => 'trim|required'
    ),

    array(
      'field' => 'phone_number',
      'label' => 'Phonenumber',
      'rules' => 'trim|required'
    ),

    array(
      'field' => 'applicable_days',
      'label' => 'Applicabledays',
      'rules' => 'trim|required',
    ),

    array(
      'field' => 'academy',
      'label' => 'Academy',
      'rules' => 'trim|required'
    ),

    array(
      'field' => 'class_type',
      'label' => 'Classtype',
      'rules' => 'trim|required'
    ),

    array(
     'field' => 'date',
     'label' => 'Date',
     'rules' => 'trim|required'
    ),

    array(
      'field' => 'hour',
      'label' => 'Hour',
      'rules' => 'trim|required'
    ),

    array(
      'field' => 'minute',
      'Label' => 'Minute',
      'rules' => 'trim|required'
    ),

    array(
      'field' => 'duration',
      'label' => 'Duration',
      'rules' => 'trim|required'
    ),

    array(
      'field' => 'class_start',
      'label' => 'Class_start',
      'rules' => 'trim|required'
    ),

    array(
      'field' => 'class_end',
      'label' => 'Class_end',
      'rules' => 'trim|required'
    )





    );

    $this->form_validation->set_rules($config);
    $this->form_validation->set_error_delimiters('', '');

    if($this->form_validation->run() === FALSE){


$result['error'] = true;
$result['msg'] = array(

  'name' => form_error('name'),
  'kr_name' => form_error('kr_name'),
  'phone_number' => form_error('phone_number'),
  'academy' => form_error('academy'),
  'class_type' => form_error('class_type'),
  'date' => form_error('date'),
  'hour' => form_error('hour'),
  'minute' => form_error('minute'),
  'duration' => form_error('duration'),
  'applicable_days' => form_error('applicable_days'),
  'class_start' => form_error('class_start'),
  'class_end' => form_error('class_end'),



);

    }

    else{

      $tutor = json_decode($this->input->post('selectedTutor'));

      $data = array(
          'name' => $this->input->post('name'),
          'kr_name' => $this->input->post('kr_name'),
          'phone_number' => $this->input->post('phone_number'),
          'academy' => $this->input->post('academy'),
          'class_type' => $this->input->post('class_type'),
          'date' => date($this->input->post('date')),
          'hour' => (int)$this->input->post('hour'),
          'applicable_days' => json_encode($this->input->post('applicable_days')),
          'duration' => (int)$this->input->post('duration'),
          'minute' => (int)$this->input->post('minute'),
          'class_start' => date($this->input->post('class_start')),
          'class_end' => date($this->input->post('class_end')),
          'skypeid' => $this->input->post('skypeId'),

          'category' => 'leveltest',
          'classid' => $this->uuid_key(),
          'conn_id' => $this->connid_key(),
          'preference_number' => $this->uuid_key()
      );


      if($student = $this->leveltest->addLevelTest($data)){
        $result['error'] = false;
        $result['msg'] = 'LevelTest added successfully';

    if($tutor !== null  && count(array($tutor))){


        $this->tutor->addClass($tutor->idx, $data);

      }

      else{

          $result['msg'] = 'No tutor selected';
      }
      }

      else{

        $result['error'] = true;
        $result['msg'] = 'Data creation failed';

      }


    }

    echo json_encode($result);

  }

  public function updateLevelTest(){

    $config = array(

    array(
      'field' => 'name',
      'label' => 'Name',
      'rules' => 'trim|required'
    ),

    array(
   'field' => 'kr_name',
   'label' => 'KoreanName',
   'rules' => 'trim|required'
 ),


    array(
      'field' => 'phone_number',
      'label' => 'Phonenumber',
      'rules' => 'trim|required'
    ),

    array(
      'field' => 'academy',
      'label' => 'Academy',
      'rules' => 'trim|required'
    ),

    array(
      'field' => 'class_type',
      'label' => 'Classtype',
      'rules' => 'trim|required'
    ),

    array(
     'field' => 'date',
     'label' => 'Date',
     'rules' => 'trim|required'
    ),

    array(
      'field' => 'hour',
      'label' => 'Hour',
      'rules' => 'trim|required'
    ),

    array(
      'field' => 'minute',
      'Label' => 'Minute',
      'rules' => 'trim|required'
    ),


    array(
    'field' => 'applicable_days',
    'label' => 'Applicabledays',
    'rules' => 'trim|required',
    ),


    array(
      'field' => 'duration',
      'label' => 'Duration',
      'rules' => 'trim|required'
    )



    );

    $this->form_validation->set_rules($config);
    $this->form_validation->set_error_delimiters('', '');

    if($this->form_validation->run() === FALSE){

  $result['error'] = true;
  $result['msg'] = array(

  'name' => form_error('name'),
  'kr_name' => form_error('kr_name'),
  'phone_number' => form_error('phone_number'),
  'academy' => form_error('academy'),
  'class_type' => form_error('class_type'),
  'date' => form_error('date'),
  'hour' => form_error('hour'),
  'minute' => form_error('minute'),
  'applicable_days' => form_error('applicable_days'),
  'duration' => form_error('duration')


  );

    }

    else{
      $idx = $this->input->post('idx');

      $data = array(
          'name' => $this->input->post('name'),
           'kr_name' => $this->input->post('kr_name'),
          'phone_number' => $this->input->post('phone_number'),
          'academy' => $this->input->post('academy'),
          'applicable_days' => json_encode($this->input->post('applicable_days')),
          'class_type' => $this->input->post('class_type'),
          'date' => date($this->input->post('date')),
          'hour' => (int)$this->input->post('hour'),
          'minute' => (int)$this->input->post('minute'),
          'duration' => (int)$this->input->post('duration')
      );

      if($this->leveltest->updateLevelTest($idx, $data)){
        $result['error'] = false;
        $result['msg'] = 'LevelTest updated successfully';

      }

      else{

        $result['error'] = true;
        $result['msg'] = 'Data not found update failed';

      }
    }

    echo json_encode($result);

  }

  public function deleteLevelTest(){

    $idx = $this->input->post('idx');
    if($this->leveltest->deleteLevelTest($idx)){

      $msg['error'] = false;
      $msg['success'] = 'Data deleted successfully';
    }
    else{

      $msg['error'] = true;
    }
    echo json_encode($msg);
  }
}
