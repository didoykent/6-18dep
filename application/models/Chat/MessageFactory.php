<?php

require APPPATH . '/models/Chat/AbstractMessageFactory.php';
require APPPATH . '/models/Chat/StudentMessage.php';

class MessageFactory extends AbstractMessageFactory {


public function createTutorMessage(){


  return new TutorMessage();
}

public function createStudentMessage(){


  return new StudentMessage();
}


}
