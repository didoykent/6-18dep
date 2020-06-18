<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Evaluation extends CI_Controller {

	function __construct(){

    parent::__construct();

    $this->load->model('Evaluation_model', 'evaluation');
		    $this->load->model('jwt_model', 'jwt');

}

public function addEvaluation(){

$config = array(

array(
  'field' => 'studentname',
  'label' => 'Studentname',
  'rules' => 'trim|required'
),




array(
  'field' => 'evaluation',
  'label' => 'Evaluation',
  'rules' => 'trim|required'
),

array(
  'field' => 'classid',
  'label' => 'Classid',
  'rules' => 'trim|required'
),


array(
  'field' => 'phone_number',
  'label' => 'Phonenumber',
  'rules' => 'trim|required'
),









);


$this->form_validation->set_rules($config);
$this->form_validation->set_error_delimiters('', '');

if($this->form_validation->run() === FALSE){


  $result['error'] = true;
  $result['msg'] = array(


    'studentname' => form_error('studentname'),




    'evaluation' => form_error('evaluation'),
    'classid' => form_error('classid'),

		'phone_number' => form_error('phone_number'),



);

}

else{

$data = array(

  'studentname' => $this->input->post('studentname'),




  'evaluation' => $this->input->post('evaluation'),
  'classid' => $this->input->post('classid'),

	'phone_number' => $this->input->post('phone_number'),

	'type' => 'regularclass',





);


if($this->evaluation->addEvaluation($data)){
	$result['error'] = false;
	$result['msg'] = 'Evaluation added successfully';


}

else{

	$result['error'] = true;
	$result['msg'] = 'Data creation failed';

}


}

echo json_encode($result);

}

public function addLevelTestEvaluation(){

	$config = array(

	array(
	  'field' => 'studentname',
	  'label' => 'Studentname',
	  'rules' => 'trim|required'
	),




	array(
	  'field' => 'evaluation',
	  'label' => 'Evaluation',
	  'rules' => 'trim|required'
	),

	array(
	  'field' => 'classid',
	  'label' => 'Classid',
	  'rules' => 'trim|required'
	),


	array(
		'field' => 'Level',
		'label' => 'Level',
		'rules' => 'trim|required'
	),

	array(
		'field' => 'Curriculum',
		'label' => 'Curriculum',
		'rules' => 'trim|required'
	),

	array(
		'field' => 'Material',
		'label' => 'Material',
		'rules' => 'trim|required'
	),


	array(
		'field' => 'phone_number',
		'label' => 'Phonenumber',
		'rules' => 'trim|required'
	),

	array(
	  'field' => 'preference_number',
	  'label' => 'Preferencenumber',
	  'rules' => 'trim|required'
	)






	);


	$this->form_validation->set_rules($config);
	$this->form_validation->set_error_delimiters('', '');

	if($this->form_validation->run() === FALSE){


	  $result['error'] = true;
	  $result['msg'] = array(


	    'studentname' => form_error('studentname'),




	    'evaluation' => form_error('evaluation'),
	    'classid' => form_error('classid'),

			'Level' => form_error('Level'),

			'Curriculum' => form_error('Curriculum'),

			'Material' => form_error('Material'),

			'phone_number' => form_error('phone_number'),

			'preference_number' => form_error('preference_number')



	);

	}

	else{

	$data = array(

	  'studentname' => $this->input->post('studentname'),




	  'evaluation' => $this->input->post('evaluation'),
	  'classid' => $this->input->post('classid'),
		'phone_number' => $this->input->post('phone_number'),
		'type' => 'leveltest',
		'preference_number' => $this->input->post('preference_number')



	);

	$classData = array(


		'Level' => $this->input->post('Level'),
		'Curriculum' => $this->input->post('Curriculum'),
		'Material' => $this->input->post('Material'),
		'preference_number' => $this->input->post('preference_number')
	);




	if(  $this->evaluation->addLevelTestEvaluation($data, $classData)){
		$result['error'] = false;
		$result['msg'] = 'Evaluation added successfully';


	}

	else{

		$result['error'] = true;
		$result['msg'] = 'Data creation failed';

	}


	}

	echo json_encode($result);


}


public function getReferenceNumber(){

	$preference_number = $this->input->post('preference_number');

	if($preference_number){
	$evaluation = $this->evaluation->getEvaluation_by_preference_number($preference_number)[0];

	if($evaluation){

		$evaluation = json_decode($evaluation->evaluation)[0];
	}
	echo json_encode($evaluation);

}
}

public function get_student_evaluations(){

	$classid = $this->input->post('classid');


	if($this->jwt->getToken() &&  $this->jwt->getToken()[0]->position === 'Student' && $classid){

		$student =  $this->jwt->getToken()[0];

		$evaluations = $this->evaluation->get_student_evaluations($student->phone_number) ? json_decode($this->evaluation->get_student_evaluations($student->phone_number)[0]->evaluation): '';



		if($evaluations){

			$classEvaluation = '';

			foreach ($evaluations as $key => $value) {

					$evaluation = json_decode($value);

					if($evaluation->classid === $classid){
										$classEvaluation = json_decode($value);

					}


			}


				echo json_encode($classEvaluation);

		}



}
}

}
