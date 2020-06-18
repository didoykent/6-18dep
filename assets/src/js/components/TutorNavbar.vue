<template>

  <div>

    <v-navigation-drawer expand-on-hover permanent fixed floating width="300" mole-break-point="991" app dark persistent>
      <v-img src="" height="100%">
        <v-list-item link @click="userSettings = !userSettings">
          <v-list-item-avatar>
            <v-img src="https://image.flaticon.com/icons/svg/265/265674.svg" height="40" min-height="40" width="40" />
          </v-list-item-avatar>
          <v-list-item-content>
            <v-list-item-title>
              LMS v0.1
            </v-list-item-title>
          </v-list-item-content>
          <v-list-item-icon>
            <v-icon>mdi-menu-down</v-icon>
          </v-list-item-icon>
        </v-list-item>
        <v-list v-if="userSettings" dense nav>
          <v-list-item-group>
            <v-list-item links>
              <v-list-item-icon text>
                PF
              </v-list-item-icon>
              <v-list-item-content>
                <v-list-item-title>
                  Profile
                </v-list-item-title>
              </v-list-item-content>
            </v-list-item>
            <v-list-item links>
              <v-list-item-icon text>
                BI
              </v-list-item-icon>
              <v-list-item-content>
                <v-list-item-title>
                  Bio
                </v-list-item-title>
              </v-list-item-content>
            </v-list-item>
          </v-list-item-group>
        </v-list>



        <v-divider></v-divider>

        <v-list nav dense>
          <v-list-item @click="$router.push('/tutor_page')" links style="background-color: #e91e63 !important;
          border-color: #e91e63 !important;">
          <v-list-item-icon>
            <v-icon>mdi-folder</v-icon>
          </v-list-item-icon>
          <v-list-item-title>Dashboard</v-list-item-title>
        </v-list-item>




        <v-list-item link @click="$router.push('tutor_writing_correction')">
          <v-list-item-icon>
            <v-icon>mdi-account-multiple</v-icon>
          </v-list-item-icon>
          <v-list-item-title>Writing Correction</v-list-item-title>
        </v-list-item>





        <v-list-item link @click="$router.push('tutor_announcement')">
          <v-list-item-icon>
            <v-icon>mdi-book-variant</v-icon>
          </v-list-item-icon>
          <v-list-item-title>Announcements</v-list-item-title>
        </v-list-item>





        <v-list-item link @click="openInbox()">
          <v-list-item-icon>
            <v-icon>mdi-clipboard-text</v-icon>
          </v-list-item-icon>
          <v-list-item-title>Chat</v-list-item-title>
        </v-list-item>



      </v-list>
    </v-img>
  </v-navigation-drawer>

  <v-dialog v-model="inboxDialog" max-width="1100"  >


    <v-card style="border-radius:0px;  box-shadow: none; ">
      <v-card-title class="headline" >
        <div class="d-flex justify-content-center align-items-center mr-2" style="height:50px;width:50px;
        background-color:#E91E63;">
        <v-icon color="white" x-large>message</v-icon>
      </div>
      Chat
    </v-card-title>
  </v-card>



    <v-card style="max-height: 500px; min-height: 500px; box-shadow:none; border-radius:0px; overflow-y: hidden;">

        <v-container class="pa-5 overflow-y-auto"  style="max-height: 500px;">

          <div v-for = "(student, index) in studentsInbox">
          <v-col @click = "openChatDialog(student)">
            <v-row >



          <v-list flat>


        <v-list-item >
          <v-list-item-icon>
            <v-avatar color="red">
        <span class="white--text headline">{{student.sender_name.charAt(0).toUpperCase()}}</span>
      </v-avatar>
          </v-list-item-icon>
        <v-list-item-content>
          <v-list-item-title>{{student.sender_name}}</v-list-item-title>
            <v-list-item-subtitle>{{student.message}}</v-list-item-subtitle>
          </v-list-item-content>


        </v-list-item>

    </v-list>

              <v-row class ="justify-end">
                  <v-list-item-action  >

                      {{student.date}}

                  </v-list-item-action>
                  </v-row>
                </v-row>


</v-col>

</div>





        </v-container>




    </v-card>


  </v-dialog>



  <v-dialog v-model="chatDialog" max-width="1100"  >


    <v-card style="border-radius:0px;  box-shadow: none; ">
      <v-card-title class="headline" >
        <div class="d-flex justify-content-center align-items-center mr-2" style="height:50px;width:50px;
        background-color:#E91E63;">
        <v-icon color="white" x-large>message</v-icon>
      </div>
      Chat
    </v-card-title>
  </v-card>



    <v-card style="max-height: 500px; min-height: 500px; box-shadow:none; border-radius:0px; overflow-y: hidden;">

        <v-container class="pa-5 overflow-y-auto"  style="max-height: 500px;">

          <div v-for = "(message, index) in Messages">
          <v-col>
            <v-row :class = "message.sender_name === Tutor.mega_name ? 'justify-end' :  '' " >



          <v-list flat 	:color = "message.sender_name === Tutor.mega_name ? 'primary' : 'grey'" >


        <v-list-item >
          <v-list-item-icon v-if = "message.sender_name !== Tutor.mega_name  ">
            <v-avatar color="red">
        <span class="white--text headline">{{message.sender_name.charAt(0).toUpperCase()}}</span>
      </v-avatar>
          </v-list-item-icon>
          <v-list-item-content>
            <div class="">{{message.message}}  </div>
          </v-list-item-content>
        </v-list-item>

    </v-list>


                </v-row>

</v-col>

</div>





        </v-container>




    </v-card>
    <v-container style="background-color: white;">
    <v-row  >


    <v-textarea
      max-width

   append-icon="mdi-send"

   label="Type here..."
   rows="1"
filled
v-model = "message"

   @click:append="sendMessage()" @keyup.enter.exact ="sendMessage()"></v-textarea>


   </v-row>
   </v-container>

  </v-dialog>

  </div>

</template>

<script>

import axios from 'axios'
export default {

  data(){

    return {
      message: '',
      Tutor: '',
      selectedStudent: '',
      Messages: [],
      studentsInbox: [],
      inboxDialog: false,

    chatDialog: false

  }
},

mounted(){

this.getStudents()
},



methods: {

  openInbox(){

    this.inboxDialog = true
  },




 async openChatDialog(student){




    const receiver_conn_id = student.receiver_conn_id
    const sender_conn_id = student.sender_conn_id

       console.log(sender_conn_id, 'stu')

  	if(receiver_conn_id || sender_conn_id){

  		const form = new FormData()

  		form.append('receiver_conn_id', receiver_conn_id)
      form.append('sender_conn_id', sender_conn_id)

  		await axios.post('Chat/getMessage', form).then(res => {

  			if(res.data){


  				const parse = JSON.parse(res.data)

  parse.forEach((item, i) => {

  parse[i] = JSON.parse(item)
  });


  				this.$set(this.$data, 'Messages', parse)







  				console.log(this.Messages, 'tez')


  			}

        this.selectedStudent = student
        this.chatDialog = true


  		})

}
  },

  async getStudents(){

  await  axios.get('Chat/getInboxStudents').then(res => {

    if(res.data){

this.$set(this.$data, 'studentsInbox', res.data.students)
this.$set(this.$data ,'Tutor', res.data.tutor)

    }

    console.log(this.studentsInbox, 'students')
    })
  },

  sendMessage(){

    if(this.message.trim() && this.selectedStudent){


  		const message = this.message
  		const receiver_conn_id = this.selectedStudent.receiver_conn_id
      const sender_conn_id = this.selectedStudent.sender_conn_id

  		const form = new FormData()
  		form.append('message', message)
  		form.append('receiver_conn_id', receiver_conn_id)
      form.append('sender_conn_id', sender_conn_id)


  		axios.post('Chat/createMessage', form).then(res => {

  			if(res.data.error === false){

  				console.log(res.data.message, 'msg')

  				this.Messages.push(res.data.message)



  			}

  			console.log(res.data, 'res')
  		})

  		this.message = ''
  	}
  }
},

sockets: {

  chat_message(data){
    if(data){
      const message = JSON.parse(data)

      console.log(message, 'nnn')
      console.log(this.selectedStudent, 'nn')
      if(message.sender_name === this.selectedStudent.sender_name){
    this.Messages.push(message)

  }

  }
    console.log(data, 'data')
  }
}
}
</script>

<style lang="css" scoped>
</style>
