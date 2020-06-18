<?php

require APPPATH . '/models/Chat/MessageInterface.php';




class StudentMessage  extends  CI_Model implements MessageInterface  {







  public function create($sender, $receiver, $message){


      $previousMessages = $this->get($sender, $receiver) ?  $this->get($sender, $receiver)[0] : '';





      if($previousMessages){

        $previous  = json_decode($previousMessages->messages, true);
        $previous[] = $message['messages'];

        $updateMessage =  array(

          'messages' =>   json_encode($previous)


        );




          return  $this->update($sender, $receiver, $updateMessage);

        }

        else{

          $newArray = array();

          $newArray[] = $message['messages'];

          $message['messages'] = json_encode($newArray);



          return    $this->db->insert('message', $message);
        }




  }

  public function getInbox($conn_id) {

  $messageSearch = "(sender_conn_id = '{$conn_id}' OR receiver_conn_id = '{$conn_id}') OR (sender_conn_id = '{$conn_id}' OR receiver_conn_id = '{$conn_id}')";


        $this->db->where($messageSearch);
        $query = $this->db->get('message');
        if($query->num_rows() > 0){

          return $query->result();
        }

        else{

          return false;
        }


}






  public function update($sender, $receiver , $message){


  $messageSearch = "(sender_conn_id = '{$sender}' AND receiver_conn_id = '{$receiver}') OR (sender_conn_id = '{$receiver}' AND receiver_conn_id = '{$sender}')";
$this->db->where($messageSearch);
    $this->db->update('message', $message);
    if($this->db->affected_rows() > 0){

      return true;
    }

    else{

      return false;
    }
  }


  public function get($sender, $receiver){

        $messageSearch = "(sender_conn_id = '{$sender}' AND receiver_conn_id = '{$receiver}') OR (sender_conn_id = '{$receiver}' AND receiver_conn_id = '{$sender}')";


    $this->db->where($messageSearch);
    $query = $this->db->get('message');
    if($query->num_rows() > 0){

      return $query->result();
    }

    else{

      return false;
    }



  }



}
