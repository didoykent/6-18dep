<template>
  <v-container fluid>
    <div class="d-flex flex-row justify-space-between">
    	<v-row justify="center">
        <v-col cols="12" md="11">
          <v-card>
            <v-card-title class="headline">
              <div class="d-flex justify-content-center align-items-center mr-2" style="height:50px;width:50px;
              background-color:#1976d2;">
              <v-icon color="white" x-large>help_outline</v-icon>
            </div>
              Q&A
            </v-card-title>
            <v-divider></v-divider>
            <v-container class="px-4">
              <v-tabs class="">
                <v-tab class="title font-weight-regular mx-4">Inbox</v-tab>
                <v-tab class="title font-weight-regular">Sent</v-tab>
                <v-tab-item>
                  <v-list two-line>
                    <v-list-item-group>
                      <template v-for="(item, index) in answered_content">
                        <v-list-item :key="item.title">
                          <template>
                            <v-list-item-avatar>
                              <v-icon x-large color="#1976d2">mdi-alpha-{{item.kr_admin_name.charAt(0).toLowerCase()}}-circle</v-icon>
                            </v-list-item-avatar>
                            <v-list-item-content @click = "selectedInboxContent(item)">
                              <v-list-item-title v-text="item.kr_admin_name"></v-list-item-title>
                              <v-list-item-subtitle class="text--primary" v-text="item.subject"></v-list-item-subtitle>
                              <v-list-item-subtitle v-text="item.content"></v-list-item-subtitle>
                            </v-list-item-content>

                            <v-list-item-action>
                              <v-list-item-action-text v-text="getTimeDiff(item.sentDate)"></v-list-item-action-text>
                            </v-list-item-action>
                          </template>
                        </v-list-item>

                        <v-divider
                          v-if="index < items.length"
                          :key="index"
                        ></v-divider>
                      </template>
                    </v-list-item-group>
                  </v-list>
                  <v-container>
                    <v-row justify="end">
                      <v-col align-self="end" cols="1">
                        <v-btn @click="writeDialog = true" color="#1976d2" class="white--text">WRITE</v-btn>
                      </v-col>
                    </v-row>
                  </v-container>
                </v-tab-item>
                <v-tab-item>
                  <v-list two-line>
                    <v-list-item-group>
                      <template v-for="(item, index) in Qa">
                        <v-list-item :key="item.qa_id">
                          <template>
                            <v-list-item-avatar>
                              <v-icon x-large color="#1976d2">mdi-alpha-{{item.category.charAt(0).toLowerCase()}}-circle</v-icon>
                            </v-list-item-avatar>
                            <v-list-item-content @click = "selectedSentContent(item)">
                              <v-list-item-title v-text="item.category"></v-list-item-title>
                              <v-list-item-subtitle class="text--primary" v-text="item.subject"></v-list-item-subtitle>
                              <v-list-item-subtitle v-text="item.content"></v-list-item-subtitle>
                            </v-list-item-content>

                            <v-list-item-action>
                              <v-list-item-action-text v-text="getTimeDiff(item.sentDate)"></v-list-item-action-text>
                            </v-list-item-action>
                          </template>
                        </v-list-item>

                        <v-divider
                          v-if="index < Qa.length"
                          :key="index"
                        ></v-divider>
                      </template>
                    </v-list-item-group>
                  </v-list>
                  <v-container>
                    <v-row justify="end">
                      <v-col align-self="end" cols="1">
                        <v-btn @click="writeDialog = true" color="#1976d2" class="white--text">WRITE</v-btn>
                      </v-col>
                    </v-row>
                  </v-container>
                </v-tab-item>
              </v-tabs>
            </v-container>

          </v-card>
        </v-col>
    	</v-row>

      <div class="float-right button-container" >
        <div class="buttons">
            <v-row class="ma-2 mb-4">
              <button class="float-right ml-2 v-btn v-btn--depressed theme--light" style="background-color:#1976d2" icon>
                <v-icon color="white" x-large>question_answer</v-icon>
              </button>
            </v-row>
          </div>
      </div>

      <v-dialog v-model="writeDialog" max-width="1000" max-height="500">
        <v-card>
          <v-card-title class="headline">
            <div class="d-flex justify-content-center align-items-center mr-2" style="height:50px;width:50px;
            background-color:#1976d2;">
            <v-icon color="white" x-large>help_outline</v-icon>
          </div>
            Q&A
          </v-card-title>
          <v-container fluid>
            <v-row>
              <v-col cols="12" sm="3">
                  <v-select v-model="category" label="Category" :items="categories"></v-select>
              </v-col>
              <v-col cols="12" sm="9">
                  <v-text-field v-model="subject" label="Subject"></v-text-field>
              </v-col>
            </v-row>
            <v-row>
              <v-col cols="12">
                <v-textarea filled placeholder="Write here ..." v-model="content"></v-textarea>
              </v-col>
            </v-row>
            <v-row class="d-flex justify-content-end">
              <v-btn text style="color:#1976d2" @click="writeDialog = false">Cancel</v-btn>
              <v-btn color="#1976d2" class="white--text mx-2" @click = "submit()">Submit</v-btn>
            </v-row>
          </v-container>
        </v-card>
      </v-dialog>

      <v-dialog v-model="inboxDialog" max-width="1000" max-height="500">
        <v-card>
          <v-card-title class="headline">
            <div class="d-flex justify-content-center align-items-center mr-2" style="height:50px;width:50px;
            background-color:#1976d2;">
            <v-icon color="white" x-large>help_outline</v-icon>
          </div>
            Q&A
          </v-card-title>
          <v-container fluid>
            <v-row>
              <v-col cols="12" sm="3">
                  <p class="title font-weight-regular">{{selectedInbox['kr_admin_name']}}</p>
              </v-col>
              <v-col cols="12" sm="9">
                  <p class="title font-weight-regular">Re: {{selectedInbox['subject']}}</p>
              </v-col>
            </v-row>
            <v-divider class="mt-0"></v-divider>
            <v-row>


              <v-col cols="12">
                      <p style="background-color:#F0F0F0" class="subtitle-1">{{selectedInbox['content']}}</p>
              </v-col>

              <v-col cols="12" class="mb-4" >
              <p>{{selectedInbox['answer']}}</p>
              </v-col>
            </v-row>
            <v-row class="d-flex justify-content-end">
              <v-btn color="#1976d2" class="white--text mx-2" @click="inboxDialog = false">Close</v-btn>
            </v-row>
          </v-container>
        </v-card>
      </v-dialog>

      <v-dialog v-model="sentDialog" max-width="1000" max-height="500">
        <v-card>
          <v-card-title class="headline">
            <div class="d-flex justify-content-center align-items-center mr-2" style="height:50px;width:50px;
            background-color:#1976d2;">
            <v-icon color="white" x-large>help_outline</v-icon>
          </div>
            Q&A
          </v-card-title>
          <v-container fluid>
            <v-row>
              <v-col cols="12" sm="3">
                  <p class="title font-weight-regular">{{selectedInbox['category']}}</p>
              </v-col>
              <v-col cols="12" sm="9">
                  <p class="title font-weight-regular">Re: {{selectedInbox['subject']}}</p>
              </v-col>
            </v-row>
            <v-divider class="mt-0"></v-divider>
            <v-row>
              <v-col cols="12">
                <p class="subtitle-1 font-weight-regular">{{selectedInbox['content']}}</p>
              </v-col>
            </v-row>
            <v-row class="d-flex justify-content-end">
              <v-btn color="#1976d2" class="white--text mx-2" @click="sentDialog = false">Close</v-btn>
            </v-row>
          </v-container>
        </v-card>
      </v-dialog>

    </div>
  </v-container>
</template>

<script>
import axios from 'axios'
import moment from 'moment'
export default {
  data: () => ({
      Qa: [],
      answered_content: [],
      selectedInbox: '',
      Student: '',
      subject: '',
      content: '',
      category: '',
      selected: [2],
      writeDialog: false,
      inboxDialog: false,
      sentDialog: false,

      categories: ['Technical Issue', 'Class Issue', 'Schedule Issue', 'Account Issue'],

      items: [
        {
          action: '15 min',
          headline: 'Brunch this weekend?',
          title: 'Ali Connors',
          subtitle: "I'll be in your neighborhood doing errands this weekend. Do you want to hang out?",
        },
        {
          action: '2 hr',
          headline: 'Summer BBQ',
          title: 'me, Scrott, Jennifer',
          subtitle: "Wish I could come, but I'm out of town this weekend.",
        },
        {
          action: '6 hr',
          headline: 'Oui oui',
          title: 'Sandra Adams',
          subtitle: 'Do you have Paris recommendations? Have you ever been?',
        },
        {
          action: '12 hr',
          headline: 'Birthday gift',
          title: 'Trevor Hansen',
          subtitle: 'Have any ideas about what we should get Heidi for her birthday?',
        },
        {
          action: '18hr',
          headline: 'Recipe to try',
          title: 'Britta Holt',
          subtitle: 'We should eat this: Grate, Squash, Corn, and tomatillo Tacos.',
        },
      ],
    }),

    mounted(){

      console.log('test')

this.getQa()



    },

    methods: {


      async getQa(){

      await axios.get('Qa/getQa').then(res => {

        console.log(res.data , 'data')
        if(res.data.student){
        if(res.data.qa){

          let qas  = res.data.qa

          let parse = JSON.parse(qas['qa'])

          parse.forEach((item, i) => {

            parse[i] = JSON.parse(item)
          });

          qas['qa']  = parse

          qas['qa'].reverse()


          const answered_content = qas['qa'].filter(data => data.answered === true)
            this.$set(this.$data, 'answered_content', answered_content)


            this.$set(this.$data, 'Qa', qas['qa'])

        }
          this.$set(this.$data, 'Student', res.data.student)

          console.log(this.answered_content, 'content')
      }

      })



    },

    getTimeDiff(sentDate){

      return moment(sentDate).fromNow();
    },


      submit(){

        if(this.subject.trim() && this.content.trim() && this.category.trim() && this.Student){

          const subject = this.subject

          const content = this.content

          const category = this.category

          const  student = this.Student

          const studentName = student['name']
          const classId = student['classid']
          const student_idx = student['idx']
          const studentConn = student['conn_id']

          const qa = {classid: classId, studentname: studentName, subject: subject, content: content, studentConn: student['conn_id'], sentDate: moment().format(), student_idx: student_idx, category: category}

          const form = new FormData()
          form.append('studentname', studentName)
          form.append('classid', classId)
          form.append('qa', JSON.stringify(qa))
          form.append('student_idx', student_idx)

          axios.post('Qa/addQa', form).then(res => {

            if(res.data.error === false){

            qa.qa_id = res.data.qa_id
            qa.answered = false


            this.$socket.emit('qa',  qa)

      location.reload()
              }
            console.log(res.data, 'res')
          })
        }
      },

      selectedInboxContent(item){
        this.selectedInbox = item
        this.inboxDialog = true

        console.log(this.selectedInbox, 's')
      },

      selectedSentContent(item){
        this.selectedInbox = item
        this.sentDialog = true

        console.log(this.selectedInbox, 's')
      },

      cancel(){
        location.reload()
      }
    },

    sockets: {

      qa_answer(data){

        if(data){

          this.answered_content.unshift(data)

          console.log(data, 'corrected')
        }
      }
    }
}
</script>

<style lang="css">

.button-container {
  width: 50px;
  position: relative;
}

.buttons {
  margin: 0;
  position: absolute;
  top: 50%;
  -ms-transform: translateY(-50%);
  transform: translateY(-50%);
}

</style>
