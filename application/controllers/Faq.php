<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Faq extends CI_Controller {

	function __construct(){

    parent::__construct();
		$this->load->model('jwt_model', 'jwt');
    $this->load->model('Faq_model', 'faq');

}



function faq_id() {
				$this->load->library('uuid');
				$id = $this->uuid->v4();
				$id = substr($id, 4);
				return $id;
}



  public function showAll(){

		 if($this->jwt->getToken()){

			 if($this->jwt->getToken()[0]->position === 'Kr_manager' || $this->jwt->getToken()[0]->position === 'Student' ){

    $query = $this->faq->showAll();

    if($query){

      $result['faq'] = $this->faq->showAll();
    }

    echo json_encode($result);

	}

}
  }



public function addFaq(){

	  if($this->jwt->getToken() &&  $this->jwt->getToken()[0]->position === 'Kr_manager'){

      $user = $this->jwt->getToken()[0];


  $config = array(

array(

  'field' => 'question',
  'label' => 'Question',
  'rules' => 'trim|required'
),

array(

'field' => 'answer',
'label' => 'Answer',
'rules' => 'trim|required'
),



);


  $this->form_validation->set_rules($config);
  $this->form_validation->set_error_delimiters('', '');

  if($this->form_validation->run() === FALSE){


    $result['error'] = true;
    $result['msg'] = array(


      'question' => form_error('question'),




      'answer' => form_error('answer'),






  );

  }

  else{


  $data = array(

    'question' => $this->input->post('question'),




    'answer' => $this->input->post('answer'),
  	'op_idx' => $user->idx,
    'op_name' => $user->mega_name,
    'faqid' => $this->faq_id(),







  );


  if ($this->faq->addFaq($data)){
  	$result['error'] = false;
  	$result['msg'] = 'faq added successfully';


  }

  else{

  	$result['error'] = true;
  	$result['msg'] = 'Data creation failed';

  }


  }

  echo json_encode($result);
}
}

public function updateFaq(){

 if($this->jwt->getToken() &&  $this->jwt->getToken()[0]->position === 'Kr_manager'){
  $config = array(

array(

  'field' => 'question',
  'label' => 'Question',
  'rules' => 'trim|required'
),

array(

'field' => 'answer',
'label' => 'Answer',
'rules' => 'trim|required'
),



);


  $this->form_validation->set_rules($config);
  $this->form_validation->set_error_delimiters('', '');

  if($this->form_validation->run() === FALSE){


    $result['error'] = true;
    $result['msg'] = array(


      'question' => form_error('question'),




      'answer' => form_error('answer'),






  );

  }

  else{

    $faqid = $this->input->post('faqid');



  $data = array(

    'question' => $this->input->post('question'),




    'answer' => $this->input->post('answer'),



  );


  if ($this->faq->updateFaq($faqid, $data)){
    $result['error'] = false;
    $result['msg'] = 'faq added successfully';


  }

  else{

    $result['error'] = true;
    $result['msg'] = 'Data creation failed';

  }


  }

  echo json_encode($result);


}

}


public function deleteFaq(){

	 if($this->jwt->getToken() &&  $this->jwt->getToken()[0]->position === 'Kr_manager'){

  $faqid = $this->input->post('faqid');
  if($this->faq->deleteFaq($faqid)){

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
