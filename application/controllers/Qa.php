<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Qa extends CI_Controller {

	function __construct(){

    parent::__construct();
		$this->load->model('jwt_model', 'jwt');
    $this->load->model('Qa_model', 'qa');

}


function qa_id() {
				$this->load->library('uuid');
				$id = $this->uuid->v4();
				$id = substr($id, 4);
				return $id;
}


public function addQa(){

$config = array(

array(
  'field' => 'studentname',
  'label' => 'Studentname',
  'rules' => 'trim|required'
),




array(
  'field' => 'qa',
  'label' => 'qa',
  'rules' => 'trim|required'
),

array(
  'field' => 'student_idx',
  'label' => 'Studentidx',
  'rules' => 'trim|required'
),

array(
  'field' => 'classid',
  'label' => 'Classid',
  'rules' => 'trim|required'
),











);


$this->form_validation->set_rules($config);
$this->form_validation->set_error_delimiters('', '');

if($this->form_validation->run() === FALSE){


  $result['error'] = true;
  $result['msg'] = array(


    'studentname' => form_error('studentname'),




    'qa' => form_error('qa'),
	  'student_idx' => form_error('student_idx'),
    'classid' => form_error('classid'),





);

}

else{
	$getQa = json_decode($this->input->post('qa'));
	$getQa->qa_id = $this->qa_id();
	$getQa->answered = false;

$data = array(

  'studentname' => $this->input->post('studentname'),




  'qa' => json_encode($getQa),
	'student_idx' => $this->input->post('student_idx'),
  'classid' => $this->input->post('classid'),








);


if($qa = $this->qa->addQa($data)){
	$result['error'] = false;
	$result['msg'] = 'qa added successfully';
	$result['qa_id'] = $getQa->qa_id;

}

else{

	$result['error'] = true;
	$result['msg'] = 'Data creation failed';

}


}

echo json_encode($result);

}


public function getAllQa(){

	  if($this->jwt->getToken() &&  $this->jwt->getToken()[0]->position === 'Kr_manager'){

			$User = $this->jwt->getToken()[0];

			$writing_qas = $this->qa->showAll();

			if($writing_qas){

				echo json_encode(	array('Qa' => $writing_qas, 'User'=> $User));
			}

		}
}

public function getQa(){

  if($this->jwt->getToken() &&  $this->jwt->getToken()[0]->position === 'Student'){

			$student = $this->jwt->getToken()[0];
			$writing_qas  = $this->qa->getQa($student->idx);


			echo json_encode(array('qa' => $writing_qas ?  $writing_qas[0] : '', 'student' => $student));

		}
}




public function set_content_Qa(){

		if($this->jwt->getToken() &&  $this->jwt->getToken()[0]->position === 'Kr_manager'){

			$user =   $this->jwt->getToken()[0];

			$contentqa = json_decode($this->input->post('contentqa'));

			if($contentqa){

					$writing_qa = $this->qa->getQa($contentqa->student_idx)[0];

					if($writing_qa){

						$student_qas  = json_decode($writing_qa->qa);

						if($student_qas){

							foreach ($student_qas as $key => $value) {

								$value = json_decode($value);

								if($value->answered === false && $value->qa_id === $contentqa->qa_id){

								$student_qas[$key] = json_encode($contentqa);
								}
							}
						}
					}

					$newData = array(

						'qa' => json_encode($student_qas)
					);

				$success = $this->qa->updateQa($contentqa->student_idx, $newData);
			}

			echo json_encode(array('success' => $success));
		}
}





}
