<?php

defined('BASEPATH') OR exit('No direct script access allowed');
class Regularclass extends CI_Controller {

  function __construct(){

    parent::__construct();

    $this->load->model('regularclass_model', 'regularclass');
      $this->load->model('tutor_model', 'tutor');
  }


  function connid_key() {
          $this->load->library('uuid');
          $id = $this->uuid->v4();
          $id = substr($id, 4);
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

    $query = $this->regularclass->showAll();

    if($query){

      $result['regularclass'] = $this->regularclass->showAll();
    }

    echo json_encode($result);
  }

  public function addRegularClass(){

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
      'Label' => 'Date',
      'rules' => 'trim|required'
    ),

    array(
      'field' => 'days',
      'Label' => 'Days',
      'rules' => 'trim|required'
    ),

    array(
      'field' => 'applicable_days',
      'label' => 'Applicabledays',
      'rules' => 'trim|required',
    ),

    array(
      'field' => 'hour',
      'label' => 'Hour',
      'rules' => 'trim|required'
    ),

    array(
      'field' => 'minute',
      'Label' => 'minuteute',
      'rules' => 'trim|required'
    ),

    array(
      'field' => 'duration',
      'label' => 'Duration',
      'rules' => 'trim|required'
    ),

    array(
      'field' => 'period',
      'label' => 'Period',
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
    ),

    array(
      'field' => 'price',
      'label' => 'Price',
      'rules' => 'trim|required'
    ),

    array(
      'field' => 'curriculum',
      'label' => 'Curriculum',
      'rules' => 'trim|required'
    ),

    array(
      'field' => 'bookMaterial',
      'label' => 'Bookmaterial',
      'rules' => 'trim|required'
    ),

    array(
      'field' => 'phone_number',
      'label' => 'Phonenumber',
      'rules' => 'trim|required'
    ),

    array(
      'field' => 'email',
      'label' => 'Email',
      'rules' => 'trim|required'
    ),









    );

    $this->form_validation->set_rules($config);
    $this->form_validation->set_error_delimiters('', '');

    if($this->form_validation->run() === FALSE){

$result['error'] = true;
$result['msg'] = array(

  'id' => form_error('id'),
  'pw' => form_error('pw'),
  'name' => form_error('name'),
  'kr_name' => form_error('kr_name'),
  'academy' => form_error('academy'),

  'class_type' => form_error('class_type'),
  'date' => form_error('date'),
  'days' => form_error('days'),
  'applicable_days' => form_error('applicable_days'),
  'hour' => form_error('hour'),
  'minute' => form_error('minute'),
  'duration' => form_error('duration'),
  'period' => form_error('period'),
  'class_start' => form_error('class_start'),
  'class_end' => form_error('class_end'),
  'price' => form_error('price'),
  'curriculum' => form_error('curriculum'),
  'bookMaterial' => form_error('bookMaterial'),
  'phone_number' => form_error('bookMaterial'),
  'email' => form_error('email')



);

    }

    else{

        $tutor = json_decode($this->input->post('selectedTutor'));





      $data = array(
          'id' => $this->input->post('id'),
          'pw' => $this->input->post('pw'),
          'name' => $this->input->post('name'),
          'kr_name' => $this->input->post('kr_name'),
          'academy' => $this->input->post('academy'),

          'class_type' => $this->input->post('class_type'),
          'date' => date($this->input->post('date')),
          'days' => $this->input->post('days'),
          'applicable_days' => json_encode($this->input->post('applicable_days')),
          'hour' => (int)$this->input->post('hour'),
          'minute' => (int)$this->input->post('minute'),
          'duration' => (int)$this->input->post('duration'),
          'period' => (int)$this->input->post('period'),
          'class_start' => json_encode($this->input->post('class_start')),
          'class_end' => json_encode($this->input->post('class_end')),
          'price' => (int)$this->input->post('price'),
          'curriculum' => $this->input->post('curriculum'),
          'bookMaterial' => $this->input->post('bookMaterial'),
          'level' => $this->input->post('level') ?  $this->input->post('level') : '',
          'phone_number' => $this->input->post('phone_number'),
          'skypeid' => $this->input->post('skypeId'),
          'category' => 'regularclass',
          'classid' => $this->uuid_key(),
          'conn_id' => $this->connid_key(),
          'email' => $this->input->post('email'),
          'preference_number' => $this->input->post('preference_number') ?  $this->input->post('preference_number') : ''
      );

      if($this->regularclass->addRegularClass($data)){
        $result['error'] = false;
        $result['msg'] = 'RegularClass added successfully';

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

  public function updateRegularClass(){



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
          'Label' => 'Date',
          'rules' => 'trim|required'
        ),

        array(
          'field' => 'days',
          'Label' => 'Days',
          'rules' => 'trim|required'
        ),

        array(
          'field' => 'applicable_days',
          'label' => 'Applicabledays',
          'rules' => 'trim|required',
        ),

        array(
          'field' => 'hour',
          'label' => 'Hour',
          'rules' => 'trim|required'
        ),

        array(
          'field' => 'minute',
          'Label' => 'minuteute',
          'rules' => 'trim|required'
        ),

        array(
          'field' => 'duration',
          'label' => 'Duration',
          'rules' => 'trim|required'
        ),

        array(
          'field' => 'period',
          'label' => 'Period',
          'rules' => 'trim|required'
        ),

        array(
          'field' => 'price',
          'label' => 'Price',
          'rules' => 'trim|required'
        ),

        array(
          'field' => 'curriculum',
          'label' => 'Curriculum',
          'rules' => 'trim|required'
        ),

        array(
          'field' => 'bookMaterial',
          'label' => 'Bookmaterial',
          'rules' => 'trim|required'
        ),

        array(
          'field' => 'phone_number',
          'label' => 'Phonenumber',
          'rules' => 'trim|required'
        ),



        array(
          'field' => 'email',
          'label' => 'Email',
          'rules' => 'trim|required'
        ),



        );

        $this->form_validation->set_rules($config);
        $this->form_validation->set_error_delimiters('', '');

        if($this->form_validation->run() === FALSE){

    $result['error'] = true;
    $result['msg'] = array(

      'id' => form_error('id'),
      'pw' => form_error('pw'),
      'name' => form_error('name'),
      'kr_name' => form_error('kr_name'),
      'academy' => form_error('academy'),

      'class_type' => form_error('class_type'),
      'date' => form_error('date'),
      'days' => form_error('days'),
      'applicable_days' => form_error('applicable_days'),
      'hour' => form_error('hour'),
      'minute' => form_error('minute'),
      'duration' => form_error('duration'),
      'period' => form_error('period'),
      'price' => form_error('price'),
      'curriculum' => form_error('curriculum'),
      'bookMaterial' => form_error('bookMaterial'),
      'phone_number' => form_error('phone_number'),

      'email' => form_error('email')



    );

        }

        else{

          $idx = $this->input->post('idx');

          $data = array(
              'id' => $this->input->post('id'),
              'pw' => $this->input->post('pw'),
              'name' => $this->input->post('name'),
              'kr_name' => $this->input->post('kr_name'),
              'academy' => $this->input->post('academy'),

              'class_type' => $this->input->post('class_type'),
              'date' => date($this->input->post('date')),
              'days' => $this->input->post('days'),
              'applicable_days' => json_encode($this->input->post('applicable_days')),
              'hour' => (int)$this->input->post('hour'),
              'minute' => (int)$this->input->post('minute'),
              'duration' => (int)$this->input->post('duration'),
              'period' => (int)$this->input->post('period'),
              'price' => (int)$this->input->post('price'),
              'curriculum' => $this->input->post('curriculum'),
              'bookMaterial' => $this->input->post('bookMaterial'),
              'phone_number' => $this->input->post('phone_number'),
              'recordings' => $this->input->post('recordings'),
              'takeover' => $this->input->post('takeover'),
              'email' => $this->input->post('email')
          );

          if($this->regularclass->updateRegularClass($idx, $data)){
            $result['error'] = false;
            $result['msg'] = 'RegularClass updated successfully';

          }

          else{

            $result['error'] = true;
            $result['msg'] = 'Data not found update failed';

          }
        }

        echo json_encode($result);


  }


  public function softUpdate(){


    $config = array(



    array(
      'field' => 'phone_number',
      'label' => 'Phonenumber',
      'rules' => 'trim|required'
    ),



    array(
      'field' => 'email',
      'label' => 'Email',
      'rules' => 'trim|required'
    ),



    );

    $this->form_validation->set_rules($config);
    $this->form_validation->set_error_delimiters('', '');

    if($this->form_validation->run() === FALSE){

$result['error'] = true;
$result['msg'] = array(


  'phone_number' => form_error('phone_number'),

  'email' => form_error('email')



);

    }

    else{

      $conn_id = $this->input->post('conn_id');

      $data = array(

          'phone_number' => $this->input->post('phone_number'),
          'recordings' => (int)$this->input->post('recordings'),
          'takeover' => (int)$this->input->post('takeover'),
          'email' => $this->input->post('email')
      );

      if($this->regularclass->updateRegularClass($conn_id, $data)){
        $result['error'] = false;
        $result['msg'] = 'RegularClass updated successfully';

      }

      else{

        $result['error'] = true;
        $result['msg'] = 'Data not found update failed';

      }
    }

    echo json_encode($result);


  }

  public function deleteRegularClass(){

    $idx = $this->input->post('idx');
    if($this->regularclass->deleteRegularClass($idx)){

      $msg['error'] = false;
      $msg['success'] = 'Data deleted successfully';
    }
    else{

      $msg['error'] = true;

    }
    echo json_encode($msg);
  }
}
