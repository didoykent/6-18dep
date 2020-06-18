<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Announcement extends CI_Controller {

	function __construct(){

    parent::__construct();
		$this->load->model('jwt_model', 'jwt');
    $this->load->model('Announcement_model', 'announcement');

}


function announcement_id() {
				$this->load->library('uuid');
				$id = $this->uuid->v4();
				$id = substr($id, 4);
				return $id;
}


public function addAnnouncement(){


	if($this->jwt->getToken() &&  $this->jwt->getToken()[0]->position !== 'Student'){

	$user = $this->jwt->getToken()[0];

$config = array(



array(
  'field' => 'subject',
  'label' => 'Subject',
  'rules' => 'trim|required'
),

array(
  'field' => 'content',
  'label' => 'Content',
  'rules' => 'trim|required'
),




array(
  'field' => 'category',
  'label' => 'Category',
  'rules' => 'trim|required'
)












);


$this->form_validation->set_rules($config);
$this->form_validation->set_error_delimiters('', '');

if($this->form_validation->run() === FALSE){


  $result['error'] = true;
  $result['msg'] = array(





    'subject' => form_error('subject'),
	  'content' => form_error('content'),
    'category' => form_error('category'),





);

}

else{

$data = array(


  'subject' => $this->input->post('subject'),
	'content' => $this->input->post('content'),
  'category' => $this->input->post('category'),
	'announcer' => $user->mega_name,
	'announcer_idx' => $user->idx,
  'announcement_id' => $this->announcement_id()

);


if($this->announcement->addAnnouncement($data)){
	$result['error'] = false;
	$result['msg'] = 'Announcement added successfully';


}

else{

	$result['error'] = true;
	$result['msg'] = 'Data creation failed';

}


}

echo json_encode($result);
}
}


public function updateAnnouncement(){


	if($this->jwt->getToken() &&  $this->jwt->getToken()[0]->position !== 'Student'){

	$user = $this->jwt->getToken()[0];

$config = array(



array(
  'field' => 'subject',
  'label' => 'Subject',
  'rules' => 'trim|required'
),

array(
  'field' => 'content',
  'label' => 'Content',
  'rules' => 'trim|required'
),




array(
  'field' => 'category',
  'label' => 'Category',
  'rules' => 'trim|required'
)












);


$this->form_validation->set_rules($config);
$this->form_validation->set_error_delimiters('', '');

if($this->form_validation->run() === FALSE){


  $result['error'] = true;
  $result['msg'] = array(





    'subject' => form_error('subject'),
	  'content' => form_error('content'),
    'category' => form_error('category'),





);

}

else{

	$announcement_id  = $this->input->post('announcement_id');

$data = array(


  'subject' => $this->input->post('subject'),
	'content' => $this->input->post('content'),
  'category' => $this->input->post('category'),
	'announcer' => $user->mega_name,
	'announcer_idx' => $user->idx,
  'announcement_id' => $announcement_id

);


if($this->announcement->updateAnnouncement($announcement_id, $data)){
	$result['error'] = false;
	$result['msg'] = 'Announcement updated successfully';


}

else{

	$result['error'] = true;
	$result['msg'] = 'Data creation failed';

}


}

echo json_encode($result);
}
}

public function deleteAnnouncement(){
	if($this->jwt->getToken() &&  $this->jwt->getToken()[0]->position !== 'Student'){

	$user = $this->jwt->getToken()[0];

	$config = array(



	array(
	'field' => 'announcement_id',
	'label' => 'Announcementid',
	'rules' => 'trim|required'
	),







	);


	$this->form_validation->set_rules($config);
	$this->form_validation->set_error_delimiters('', '');

	if($this->form_validation->run() === FALSE){


	$result['error'] = true;
	$result['msg'] = array(





		'announcement_id' => form_error('announcement_id'),






	);

	}

	else{

	$announcement_id  = $this->input->post('announcement_id');




	if($this->announcement->deleteAnnouncement($announcement_id)){
	$result['error'] = false;
	$result['msg'] = 'Announcement Removed successfully';


	}

	else{

	$result['error'] = true;
	$result['msg'] = 'Data removal failed';

	}


	}

	echo json_encode($result);
	}

}

public function getAnnouncement(){

  if($this->jwt->getToken()){

		$category = $this->input->post('category');
		$user = $this->jwt->getToken()[0];
		$announcements = '';
		if($category === 'KR ADMIN' && $user->position === 'Kr_manager'){


			$announcements = $this->announcement->getAnnouncement($category);

		}

		if($category === 'ALL ADMIN'  && $user->position !== 'Tutor' && $user->position !== 'Student'){

				$announcements = $this->announcement->getAnnouncement($category);
		}

		if($category === 'ALL TUTOR'  && $user->position !== 'Student'){

				$announcements = $this->announcement->getAnnouncement($category);
		}

		echo json_encode(['announcements' => $announcements, 'user' => $user]);
}

}







}
