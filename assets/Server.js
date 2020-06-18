var app = require('express');

var server = require('http').Server(app);

var io = require('socket.io')(server);

var redis = require('redis');

const axios = require('axios');

let Users = [];


server.listen(7740);

var redisClient = redis.createClient();

redisClient.subscribe('notif');
redisClient.subscribe('chat');

redisClient.on('message', function(channel, message){



if(message.trim() && channel === 'notif'){

const user = JSON.parse(message)

if(user){

  Users.push(user.conn_id)
}
console.log(Users, 'users')

}

if(message && channel === 'chat'){


   io.sockets.emit('chat_message', message)

  console.log(message,'message')


})
 io.on('connection', function(socket){

   console.log('Client connected')

   socket.on('student_writing_correction', function(message){

     if(message){

       io.sockets.emit('tutor_writing_correction', message)
     }

     console.log(message, 'correction')
   })


   socket.on('set_content_correction', function(message) {

     if(message){

       io.sockets.emit('tutor_corrected_content', message)

       console.log(message)
     }
   })

   socket.on('qa', function(message) {


     if(message){

       io.sockets.emit('student_qa', message)

       console.log(message)
     }
   })

   socket.on('qa_reply', function(message){

     if(message){

       io.sockets.emit('qa_answer', message)
       console.log(message)
     }
   })



   socket.on('disconnect', function(){


   })
 });
