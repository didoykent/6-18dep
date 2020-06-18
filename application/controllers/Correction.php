<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Correction extends CI_Controller {

	function __construct(){

    parent::__construct();
		$this->load->model('jwt_model', 'jwt');
    $this->load->model('Correction_model', 'correction');

}


function correction_id() {
				$this->load->library('uuid');
				$id = $this->uuid->v4();
				$id = substr($id, 4);
				return $id;
}


public function addCorrection(){

$config = array(

array(
  'field' => 'studentname',
  'label' => 'Studentname',
  'rules' => 'trim|required'
),




array(
  'field' => 'correction',
  'label' => 'correction',
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




    'correction' => form_error('correction'),
	  'student_idx' => form_error('student_idx'),
    'classid' => form_error('classid'),





);

}

else{
	$getCorrection = json_decode($this->input->post('correction'));
	$getCorrection->correction_id = $this->correction_id();
	$getCorrection->corrected = false;

$data = array(

  'studentname' => $this->input->post('studentname'),




  'correction' => json_encode($getCorrection),
	'student_idx' => $this->input->post('student_idx'),
  'classid' => $this->input->post('classid'),








);


if($correction = $this->correction->addcorrection($data)){
	$result['error'] = false;
	$result['msg'] = 'correction added successfully';
	$result['correction_id'] = $getCorrection->correction_id;

}

else{

	$result['error'] = true;
	$result['msg'] = 'Data creation failed';

}


}

echo json_encode($result);

}


public function getAllCorrections(){

	  if($this->jwt->getToken() &&  $this->jwt->getToken()[0]->position === 'Kr_manager'){

			$writing_corrections = $this->correction->showAll();

			if($writing_corrections){

				echo json_encode($writing_corrections);
			}

		}
}

public function getCorrection(){

  if($this->jwt->getToken() &&  $this->jwt->getToken()[0]->position === 'Student'){

			$student = $this->jwt->getToken()[0];
			$writing_corrections  = $this->correction->getCorrection($student->idx);

			if($writing_corrections){


				echo json_encode($writing_corrections[0]);
			}

		}
}


public function getTutorCorrection(){

	if($this->jwt->getToken()){

		$user = $this->jwt->getToken()[0];

		$corrections  = $this->correction->getTutorCorrection($user->conn_id);

		$class_corrections = array();

		if($corrections){



			foreach ($corrections as $key => $value) {

			$correction = json_decode($value->correction);
			if($correction){
				foreach ($correction as $c => $v) {

					$decode = json_decode($v);

					if($decode->tutorConn === $user->conn_id){

						$class_corrections[] = $decode;
					}
				}
}
			}


		}
			echo json_encode($class_corrections);
		}
}

public function set_content_correction(){

		if($this->jwt->getToken()){

			$contentCorrection = json_decode($this->input->post('contentCorrection'));

			if($contentCorrection){

					$writing_correction = $this->correction->getCorrection($contentCorrection->student_idx)[0];

					if($writing_correction){

						$student_corrections  = json_decode($writing_correction->correction);

						if($student_corrections){

							foreach ($student_corrections as $key => $value) {

								$value = json_decode($value);

								if($value->corrected === false && $value->correction_id === $contentCorrection->correction_id){

								$student_corrections[$key] = json_encode($contentCorrection);
								}
							}
						}
					}

					$newData = array(

						'correction' => json_encode($student_corrections)
					);

				$success = $this->correction->updatecorrection($contentCorrection->student_idx, $newData);
			}

			echo json_encode(array('success' => $success));
		}
}





}
