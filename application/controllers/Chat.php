<?php



require_once APPPATH . 'libraries/codeigniter-predis/src/Redis.php';


class Chat extends CI_Controller
{
    public function __construct()
    {
        parent::__construct();


            $this->redis = new \CI_Predis\Redis();
            $this->load->model('jwt_model', 'jwt');
            $this->load->model('Chat/MessageFactory', 'chat');
            $this->load->model('Tutor_model', 'tutor');
    }

    function chat_id() {
    				$this->load->library('uuid');
    				$id = $this->uuid->v4();
    				$id = substr($id, 4);
    				return $id;
    }


    public function getInboxStudents(){


          if($this->jwt->getToken() ){

            $tutor = $this->jwt->getToken()[0];

          $getTutorData = $this->tutor->getTutor($tutor->idx)[0];


            $constructData = array();


            $schedules = json_decode($getTutorData->class_schedule);
if($schedules){

  $studentMessage =    $this->chat->createStudentMessage();

  $students = array();
  $get = $studentMessage->getInbox($getTutorData->conn_id);
            foreach ($schedules as $index => $schedule) {

            if($schedule->active === true && $schedule->cancelled === false){



              $constructData['sender_conn_id'] = $getTutorData->conn_id;
              $constructData['receiver_conn_id'] =  $schedule->schedule->conn_id;
              $constructData['sender_name'] = $schedule->schedule->name;

              if($get){

              foreach ($get as $key => $value) {

                if($value->sender_conn_id === $schedule->schedule->conn_id || $value->receiver_conn_id === $schedule->schedule->conn_id){
                $message =  json_decode($value->messages, true);
                $end =   end($message);
                $constructData['message'] = json_decode($end)->message;
                $constructData['date'] = json_decode($end)->date;


              }

              }

            }


            $students[] = $constructData;

            }
          }


}




            echo json_encode(array('students' => $students, 'tutor' => $tutor));



          }
    }


  public function getMessage(){


    $receiver =   $this->input->post('receiver_conn_id');
    $sender2 =  $this->input->post('sender_conn_id');

    if($this->jwt->getToken()){

      $sender = $this->jwt->getToken()[0]->conn_id;

      $receiver = $receiver === $sender ? $sender2 : $receiver;

      $studentMessage = $this->chat->createStudentMessage();


      $get = $studentMessage->get($sender, $receiver) ?  $studentMessage->get($sender, $receiver)[0] : '';



      echo json_encode($get ? $get->messages : '');

    }
}


public function createMessage(){


  if($this->jwt->getToken()){

    $user =  $this->jwt->getToken()[0];



    $config = array(

  array(

    'field' => 'receiver_conn_id',
    'label' => '',
    'rules' => 'trim|required'
  ),

  array(

  'field' => 'message',
  'label' => 'Message',
  'rules' => 'trim|required'
  ),



  );


    $this->form_validation->set_rules($config);
    $this->form_validation->set_error_delimiters('', '');

    if($this->form_validation->run() === FALSE){


      $result['error'] = true;
      $result['msg'] = array(


        'receiver_conn_id' => form_error('receiver_conn_id'),




        'message' => form_error('message'),






    );

    }

    else{


      $sender2 = $this->input->post('sender_conn_id');
      $receiver = $this->input->post('receiver_conn_id');

      $receiver = $receiver === $user->conn_id ? $sender2 : $receiver;
      $messages = array(


        'receiver_conn_id' => $receiver,
        'sender_conn_id' => $user->conn_id,
        'sender_name' => property_exists($user, 'mega_name') ? $user->mega_name  : $user->name,
        'chat_id' => $this->chat_id(),
        'message' => $this->input->post('message'),
        'date' => Date('Y-m-d h:i:s')

      );


    $data = array(



    	'receiver_conn_id' => $messages['receiver_conn_id'],
      'sender_conn_id' => $user->conn_id,
      'chat_id' => $messages['chat_id'],
      'messages' => json_encode($messages)


    );

      $studentMessage = $this->chat->createStudentMessage();

    if(  $studentMessage->create($data['sender_conn_id'], $data['receiver_conn_id'], $data)) {
      $result['error'] = false;
      $result['msg'] = 'message added successfully';
      $result['message'] = $messages;
      $this->redis->publish('chat', $data['messages']);
    }




    else{

    	$result['error'] = true;
    	$result['msg'] = 'Data creation failed';

    }


    }

    echo json_encode($result);
  }
}
}
