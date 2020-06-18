<template>
  <v-container fluid>
    <div class="d-flex flex-row justify-space-between">
    	<v-row justify="center">
        <v-col cols="12" md="11">
          <v-card>
            <v-card-title class="headline">
              <div class="d-flex justify-content-center align-items-center mr-2" style="height:50px;width:50px;
              background-color:#1976d2;">
              <v-icon color="white" x-large>create</v-icon>
            </div>
              Writing Correction
            </v-card-title>
            <v-divider></v-divider>
            <v-container class="px-4">
              <v-tabs class="">
                <v-tab class="title font-weight-regular mx-4">Inbox</v-tab>
                <v-tab class="title font-weight-regular">Sent</v-tab>
                <v-tab-item>
                  <v-list two-line>
              <v-list-item-group>
                <template v-for="(item, index) in correctedContent">
                  <v-list-item :key="item.correction_id">
                    <template>
                      <v-list-item-avatar>
                        <v-icon x-large color="#1976d2">mdi-alpha-{{item.tutorName.charAt(0).toLowerCase()}}-circle</v-icon>
                      </v-list-item-avatar>
                      <v-list-item-content @click = "selectedInboxContent(item)">
                        <v-list-item-title  style="text-transform: capitalize;" v-text="item.tutorName"></v-list-item-title>
                        <v-list-item-subtitle class="text--primary" v-text="item.subject"></v-list-item-subtitle>
                        <v-list-item-subtitle v-text="item.content"></v-list-item-subtitle>
                      </v-list-item-content>

                      <v-list-item-action>
                        <v-list-item-action-text v-text="getTimeDiff(item.sentDate)"></v-list-item-action-text>
                      </v-list-item-action>
                    </template>
                  </v-list-item>

                  <v-divider
                    v-if="index < correctedContent.length"
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
                <template v-for="(item, index) in writing_corrections">
                  <v-list-item :key="item.correction_id">
                    <template>
                      <v-list-item-avatar>
                        <v-icon x-large color="#1976d2">mdi-alpha-{{item.tutorName.charAt(0).toLowerCase()}}-circle</v-icon>
                      </v-list-item-avatar>
                      <v-list-item-content @click = "sentData(item)">
                        <v-list-item-title  style="text-transform: capitalize;" v-text="item.tutorName"></v-list-item-title>
                        <v-list-item-subtitle class="text--primary" v-text="item.subject"></v-list-item-subtitle>
                        <v-list-item-subtitle v-text="item.content"></v-list-item-subtitle>
                      </v-list-item-content>

                      <v-list-item-action>
                        <v-list-item-action-text v-text="getTimeDiff(item.sentDate)"></v-list-item-action-text>
                      </v-list-item-action>
                    </template>
                  </v-list-item>

                  <v-divider
                    v-if="index < items.writing_corrections"
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
            <v-icon color="white" x-large>create</v-icon>
          </div>
            Write
          </v-card-title>
          <v-container fluid>
            <v-row>
              <v-col cols="12" sm="3">
                  <v-select    label="Teacher" :items="Tutors" item-text = "mega_name"  item-value="idx" v-model = "selectedTutor"></v-select>
              </v-col>
              <v-col cols="12" sm="9">
                  <v-text-field v-model="subject" label="Subject" ></v-text-field>
              </v-col>
            </v-row>
            <v-row>
              <v-col cols="12">
                <v-textarea filled placeholder="Write here ..." v-model="Content"></v-textarea>
              </v-col>
            </v-row>
            <v-row class="d-flex justify-content-end">
              <v-btn text style="color:#1976d2" @click ="cancel()">Cancel</v-btn>
              <v-btn color="#1976d2" class="white--text mx-2" @click = "submit">Submit</v-btn>
            </v-row>
          </v-container>
        </v-card>
      </v-dialog>

    </div>

    <v-dialog v-model="inboxDialog" max-width="1000" max-height="500">
      <v-card>
        <v-card-title class="headline">
          <div class="d-flex justify-content-center align-items-center mr-2" style="height:50px;width:50px;
          background-color:#1976d2;">
          <v-icon color="white" x-large>create</v-icon>
        </div>
          Write
        </v-card-title>
        <v-container fluid>
          <v-row>
            <v-col cols="12" sm="3">
                <p style="text-transform: capitalize;" class="title font-weight-regular">{{selectedInbox['tutorName']}}</p>
            </v-col>
            <v-col cols="12" sm="9">
                <p style="text-transform: capitalize;" class="title font-weight-regular">{{selectedInbox['subject']}}</p>
            </v-col>
          </v-row>
          <v-divider class="mt-0"></v-divider>
          <v-row>
            <v-col cols="12">
              <p class="subtitle-1 font-weight-regular grey--text">{{selectedInbox['content']}}</p>
              <p class="subtitle-1 font-weight-regular black--text">{{selectedInbox['correctedContent']}}</p>
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
          <v-icon color="white" x-large>create</v-icon>
        </div>
          Write
        </v-card-title>
        <v-container fluid>
          <v-row>
            <v-col cols="12" sm="3">
                <p  style="text-transform: capitalize;" class="title font-weight-regular">{{selectedInbox['tutorName']}}</p>
            </v-col>
            <v-col cols="12" sm="9">
                <p  style="text-transform: capitalize;" class="title font-weight-regular">{{selectedInbox['subject']}}</p>
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

  </v-container>


</template>

<script>
import axios from 'axios'
import moment from 'moment'
export default {
  data: () => ({
    selectedInbox: '',
    correctedContent: [],
    writing_corrections: [],
    Content: '',
    selectedTutor: '',
    subject: '',
    Student: '',
    Tutors: [],
      selected: [2],
      writeDialog: false,
      inboxDialog: false,
      sentDialog: false,
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

    this.getTutors()

    this.getCorrection()
    },






    methods: {

    async  getTutors(){

      await axios.get('Student/getTutors').then(res => {


        if(res.data.tutors){

          this.$set(this.$data, 'Tutors', res.data.tutors)
          this.$set(this.$data, 'Student', res.data.student)
        }
        console.log(res.data, 'res')
      })
    },

  async getCorrection(){

        axios.get('Correction/getCorrection').then(res => {
          if(res.data){

            let corrections  = res.data

            let parse = JSON.parse(corrections['correction'])

            parse.forEach((item, i) => {

              parse[i] = JSON.parse(item)
            });

            corrections['correction']  = parse
            corrections['correction'].reverse()
            const corrected_content = corrections['correction'].filter(data => data.corrected === true)


            this.$set(this.$data, 'writing_corrections',   corrections['correction'])
            this.$set(this.$data, 'correctedContent', corrected_content)


          }


        })
    },

    submit(){

       let tutorIndex =  this.selectedTutor ? this.Tutors.findIndex(tutor => tutor.idx === this.selectedTutor) : ''

       const selectedTutor = tutorIndex >= 0 ? this.Tutors[tutorIndex] : ''


      if(this.subject.trim() && selectedTutor && this.Content.trim() && this.Student){



        const subject = this.subject

        const content = this.Content
        const student = this.Student
        console.log(selectedTutor, 'idx')
        const studentName = student['name']
        const classId = student['classid']
        const student_idx = student['idx']
        const studentConn = student['conn_id']

        const correction = {classid: classId, studentname: studentName, tutorName: selectedTutor['mega_name'], tutorConn: selectedTutor['conn_id'], subject: subject, content: content, studentConn: student['conn_id'], sentDate: moment().format(), student_idx: student_idx}

        console.log(correction,  'corr')
        const form = new FormData()

          form.append('studentname', studentName)
          form.append('classid', classId)
          form.append('correction', JSON.stringify(correction))
          form.append('student_idx', student_idx)

        axios.post('Correction/addCorrection', form).then(res => {

        if(res.data.error === false){

          const correction_id = res.data.correction_id

        this.$socket.emit('student_writing_correction', {subject: subject,  tutorName: selectedTutor['mega_name'], tutorConn: selectedTutor['conn_id'], content: content, studentname:studentName, studentConn:studentConn, classid: classId, sentDate: moment().format(), correction_id: correction_id, corrected:false, student_idx: student_idx})

location.reload()
          }
        })


      }

    },

    getTimeDiff(sentDate){

      return moment(sentDate).fromNow();
    },

    sentData(item){

        this.selectedInbox = item

        console.log(this.selectedInbox)

        this.sentDialog = true
    },

  selectedInboxContent(item){
    this.selectedInbox = item
    this.inboxDialog = true

    console.log(this.selectedInbox, 's')
  },

  cancel(){
    location.reload()
  }
  },

  sockets: {

    tutor_corrected_content(data){

      if(data){

        this.correctedContent.unshift(data)

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
