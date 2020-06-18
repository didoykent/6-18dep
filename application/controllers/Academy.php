<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Academy extends CI_Controller {

	function __construct(){

    parent::__construct();
		$this->load->model('jwt_model', 'jwt');
    $this->load->model('academy_model', 'academy');

}



function academy_id() {
				$this->load->library('uuid');
				$id = $this->uuid->v4();
				$id = substr($id, 4);
				return $id;
}



  public function showAll(){

		 if($this->jwt->getToken()){



    $query = $this->academy->showAll();

    if($query){

      $result['academy'] = $this->academy->showAll();
    }

    echo json_encode($result);



}
  }



public function addAcademy(){

	  if($this->jwt->getToken()){

      $user = $this->jwt->getToken()[0];


  $config = array(

array(

  'field' => 'name',
  'label' => 'Name',
  'rules' => 'trim|required'
),

array(

  'field' => 'website',
  'label' => 'Website',
  'rules' => 'trim|required'
),

array(

  'field' => 'description',
  'label' => 'Description',
  'rules' => 'trim|required'
),

array(

  'field' => 'special_instruction',
  'label' => 'Specialinstruction',
  'rules' => 'trim|required'
),

array(

  'field' => 'cs_number',
  'label' => 'Csnumber',
  'rules' => 'trim|required'
),

array(

  'field' => 'calling_prefix',
  'label' => 'Callingprefix',
  'rules' => 'trim|required'
),





);


  $this->form_validation->set_rules($config);
  $this->form_validation->set_error_delimiters('', '');

  if($this->form_validation->run() === FALSE){


    $result['error'] = true;
    $result['msg'] = array(


       'name' => form_error('name'),
			 'website' => form_error('website'),
			 'description' => form_error('  description'),
			 'special_instruction' => form_error('special_instruction'),
			 'cs_number' => form_error('cs_number'),
			 'calling_prefix' => form_error('calling_prefix'),











  );

  }

  else{


  $data = array(

    'name' => $this->input->post('name'),
		'website' => $this->input->post('website'),
		'description' => $this->input->post('description'),
		'special_instruction' => $this->input->post('special_instruction'),
		'cs_number' => $this->input->post('cs_number'),
	  'calling_prefix' => $this->input->post('calling_prefix'),
    'academyid' => $this->academy_id(),







  );


  if ($this->academy->addacademy($data)){
  	$result['error'] = false;
  	$result['msg'] = 'academy added successfully';


  }

  else{

  	$result['error'] = true;
  	$result['msg'] = 'Data creation failed';

  }


  }

  echo json_encode($result);
}
}

public function updateacademy(){

 if($this->jwt->getToken()){
	 $config = array(

 array(

   'field' => 'name',
   'label' => 'Name',
   'rules' => 'trim|required'
 ),

 array(

   'field' => 'website',
   'label' => 'Website',
   'rules' => 'trim|required'
 ),

 array(

   'field' => 'description',
   'label' => 'Description',
   'rules' => 'trim|required'
 ),

 array(

   'field' => 'special_instruction',
   'label' => 'Specialinstruction',
   'rules' => 'trim|required'
 ),

 array(

   'field' => 'cs_number',
   'label' => 'Csnumber',
   'rules' => 'trim|required'
 ),

 array(

   'field' => 'calling_prefix',
   'label' => 'Callingprefix',
   'rules' => 'trim|required'
 ),





 );


  $this->form_validation->set_rules($config);
  $this->form_validation->set_error_delimiters('', '');

  if($this->form_validation->run() === FALSE){


    $result['error'] = true;
    $result['msg'] = array(


			'name' => form_error('name'),
			'website' => form_error('website'),
			'description' => form_error('  description'),
			'special_instruction' => form_error('special_instruction'),
			'cs_number' => form_error('cs_number'),
			'calling_prefix' => form_error('calling_prefix'),









  );

  }

  else{

    $academyid = $this->input->post('academyid');



		$data = array(

			'name' => $this->input->post('name'),
			'website' => $this->input->post('website'),
			'description' => $this->input->post('description'),
			'special_instruction' => $this->input->post('special_instruction'),
			'cs_number' => $this->input->post('cs_number'),
			'calling_prefix' => $this->input->post('calling_prefix'),




  );


  if ($this->academy->updateacademy($academyid, $data)){
    $result['error'] = false;
    $result['msg'] = 'academy added successfully';


  }

  else{

    $result['error'] = true;
    $result['msg'] = 'Data creation failed';

  }


  }

  echo json_encode($result);


}

}


public function deleteacademy(){

	 if($this->jwt->getToken()){

  $academyid = $this->input->post('academyid');
  if($this->academy->deleteacademy($academyid)){

    $msg['error'] = false;
    $msg['success'] = 'Data deleted successfully';
  }
  else{

    $msg['error'] = true;

  }
  echo json_encode($msg);

}
}


}
