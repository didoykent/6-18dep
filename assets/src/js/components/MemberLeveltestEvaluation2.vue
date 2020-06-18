<template>
  <v-container>

    <v-row>
      <v-col :cols="leftColumn">
        <v-card flat style="width:100%;height:100%">
          <v-container>
            <v-row>
              <iframe class="iframe-placeholder" src="http://178.128.213.14/" style="height:600px;width:92%"></iframe>
              <v-spacer></v-spacer>
              <v-icon large color="primary" @click="showMenu">{{arrow}}</v-icon>
            </v-row>
          </v-container>
        </v-card>
      </v-col>
      <v-col :cols="rightColumn">
        <v-card :style="rightStyle">
          <v-card-title class="headline">
            <div class="d-flex justify-content-center align-items-center mr-2" style="height:50px;width:50px;
            background-color:#E91E63;">
            <v-icon color="white" x-large>check</v-icon>
          </div>
          Student's Level Test
        </v-card-title>
        <v-stepper v-model="stepper" alt-labels flat>
          <v-stepper-header>
            <v-stepper-step :complete="stepper > 1" step="1">Scores</v-stepper-step>
            <v-divider></v-divider>
            <v-stepper-step step="2">Material</v-stepper-step>
          </v-stepper-header>

          <v-stepper-items>
            <v-stepper-content step="1">
              <v-container>
                <v-row>
                  <v-col cols="12">
                    <v-select   v-model = "Attendance" label="Attendance" :items="attendance"></v-select>
                  </v-col>
                </v-row>
                <v-row>
                  <v-col cols="12">
                    <v-select  v-model = "Level" label="Level" :items="levels"></v-select>
                  </v-col>
                </v-row>
                <v-row>
                  <v-col cols="12" md="4" class="pb-0">
                    <v-select   v-model = "Pronunciation"  label="Pronunciation" :items="scores"></v-select>
                  </v-col>
                  <v-col cols="12" class="pt-0">
                    <v-textarea  v-model = "PronunciationComment" filled label="Comment"></v-textarea>
                  </v-col>
                </v-row>
                <v-row>
                  <v-col cols="12" md="4" class="pb-0">
                    <v-select  v-model = "Grammar" label="Grammar" :items="scores"></v-select>
                  </v-col>
                  <v-col cols="12" class="pt-0">
                    <v-textarea  v-model = "GrammarComment" filled label="Comment"></v-textarea>
                  </v-col>
                </v-row>
                <v-row>
                  <v-col cols="12" md="4" class="pb-0">
                    <v-select  v-model = "Comprehension" label="Comprehension" :items="scores"></v-select>
                  </v-col>
                  <v-col cols="12" class="pt-0">
                    <v-textarea  v-model = "ComprehensionComment" filled label="Comment"></v-textarea>
                  </v-col>
                </v-row>
                <v-row>
                  <v-col cols="12" md="4" class="pb-0">
                    <v-select  v-model = "Fluency" label="Fluency" :items="scores"></v-select>
                  </v-col>
                  <v-col cols="12" class="pt-0">
                    <v-textarea  v-model = "FluencyComment" filled label="Comment"></v-textarea>
                  </v-col>
                </v-row>
                <v-row class="d-flex justify-content-end">
                  <v-btn text>Close</v-btn>
                  <v-btn @click="stepper = 2" color="#E91E63" class="white--text">Next</v-btn>
                </v-row>
              </v-container>
            </v-stepper-content>
            <v-stepper-content step="2">
              <v-container>
                    <v-row>
                      <v-col cols="12">
                        <v-select label="Curriculum"  v-model = "Curriculum" :items="curriculums" @change="onChangeCurriculum($event)"></v-select>
                      </v-col>
                    </v-row>
                    <v-row>
                      <v-col cols="12">
                        <v-select  v-model = "Material" label="Material"  :items="books"></v-select>
                      </v-col>
                    </v-row>
                    <v-row>
                      <v-col cols="12">
                        <v-textarea filled  v-model = "TeachersNote" label="Teacher's Note"></v-textarea>
                      </v-col>
                    </v-row>

                <v-row class="d-flex justify-content-end">
                  <v-btn text>Close</v-btn>
                  <v-btn text color="#E91E63" @click="stepper = 1">Back</v-btn>
                  <v-btn color="#E91E63" class="white--text" @click = "addLevelTestEvaluation()">Submit</v-btn>
                </v-row>
              </v-container>
            </v-stepper-content>
          </v-stepper-items>
        </v-stepper>
      </v-card>
    </v-col>
  </v-row>


</v-container>
</template>


<style scoped>
  .v-expansion-panel-header{
    padding-top: 0px;
    padding-bottom: 0px;
  }
</style>

<script>
import vue from 'vue'
import axios from 'axios'
import moment from 'moment'

export default {
  data() {
    return {
      Tutor: [],
      EvaluationError: false,
      Class: [],
      Attendance: '',
      Level: '',
      Curriculum: '',
      Material: '',
      Pronunciation: '',
      PronunciationComment: '',
      Grammar: '',
      GrammarComment: '',
      Comprehension: '',
      ComprehensionComment: '',
      Fluency: '',
      FluencyComment: '',
      TeachersNote: '',
      Lesson: '',
      pageNumber: '',
      Constructed1: '',
      Constructed2: '',
      Corrected1: '',
      Corrected2: '',
      encounteredWord1: '',
      encounteredWord2: '',
      Daily1: '',
      Daily2: '',
      selfStudy: '',
      arrow: 'arrow_left',
      date: new Date().toISOString().substr(0, 10),
      time: new Date().toLocaleString("en-US", {
        timeZone: "Asia/Seoul"
      }).substr(11, 21),

      isMenuShowing: false,
      stepper: 1,
      tab1: null,
      tab2: null,

      updateLevelText: 'Update',
      updateCurriculumMaterialText: 'Update',

      attendance: ['Present', 'Absent'],

      scores: ['1', '2', '3', '4', '5', '6', '7', '8', '9'],

      levels: ['Low Beginner', 'Beginner', 'High Beginner', 'Low Intermediate',
      'Intermediate', 'High Intermediate',
      'Pre Advance', 'Advance', 'Post Advance'
    ],

    curriculums: ['Freetalking', 'Introductory Course', 'Elementary/Intermediate Conversation Course',
    'Regular Conversation', 'New York Live English', 'Grammar Pattern Course', 'Beginner Discussion',
    'Business Course', 'Specialized Job Preparation Course', 'Discussion/Free Talking Course'
  ],

  books: [],

  book_introductory_course: ['Phonics 1', 'Phonics 2', 'Phonics 3', 'Phonics 4', 'Phonics 5', 'Phonics 6',
  'Pattern Practice Junior Basic', 'Pattern Practice Junior Intermediate', 'Pattern Practice Junior Advanced',
  'Conversation Junior Basic', 'Conversation Junior Intermediate', 'Conversation Junior Advanced',
  'Advanced Phonics 1', 'Advanced Phonics 2', 'Advanced Phonics 3'
],

book_elementary_course: ['Milestones 1', 'Milestones 2', 'Milestones 3', 'First Step in Conversation 1',
'First Step in Conversation 2', 'First Step in Conversation 3'
],

book_regular_conversation: ['Conversation 1', 'Conversation 2', 'Conversation 3', 'Conversation 4', 'Conversation 5',
'Interactive English Beginner 1', 'Interactive English Beginner 2', 'Interactive English Beginner 3',
'Interactive English Intermediate 1', 'Interactive English Intermediate 2', 'Interactive English Intermediate 3',
'Interactive English Upper Intermediate 1', 'Interactive English Upper Intermediate 2', 'Interactive English Upper Intermediate 3',
'Interactive English Advanced 1', 'Interactive English Advanced 2', 'Interactive English Advanced 3'
],


book_grammar_pattern: ['Speaking Pattern Drills 1', 'Speaking Pattern Drills 2', 'Speaking Pattern Drills 4', 'Speaking Pattern Drills 5',
'Pattern Practice Adult 1', 'Pattern Practice Adult 2', 'Pattern Practice Adult 3'
],

book_beginner_discussion: ['Easy Topics for Discussion 1', 'Easy Topics for Discussion 2', 'Easy Topics for Discussion 3', 'Easy Topics for Discussion 4',
'Easy Topics for Discussion 5', "Let's Discuss 1", "Let's Discuss 2", "Let's Discuss 3", "Let's Discuss 4", "Let's Discuss 5"
],

book_business_course: ['Business English (Situational Dialogues)', 'Emailing', 'Meeting', 'Negotiation',
'Presentation', 'Business English (Discussion and Analysis)'
],

book_specialize_job_preparation_course: ['Interview', 'Hotel Dialogues', 'Cabin Crew', 'IELTS', 'Medical English',
'Tomato Opic', 'Getting Ready for TOEIC Speaking', 'Opic Advanced', 'Actual TOEIC Speaking'
],

book_discussion_course: ['English Conversation Situation Training 1', 'English Conversation Situation Training 2', 'English Conversation Situation Training 3',
'English Convesation Training Patten Drill 1', 'English Convesation Training Patten Drill 2', 'English Convesation Training Patten Drill 3',
'English Convesation Training Verb Drill 1', 'English Convesation Training Verb Drill 2', 'English Convesation Training Verb Drill 3',
'BIZ E-MAIL ENGLISH', 'BIZ TELEPHONE ENGLISH', 'BIZ PRESENTATION ENGLISH', 'BIZ MEETING DISCUSSION ENGLISH'
],

}
},

mounted() {
  this.leftColumn = 6
  this.rightColumn = 6
  this.rightStyle = ''
  this.isMenuShowing = true
  this.arrow = 'arrow_right'


  const classId = this.$route.params.classid

  const form = new FormData();

  form.append('classId', classId)
  axios.post('Tutor/getStudent', form).then(res => {

    console.log(res.data , 'res')

    if(res.data.evaluation){

      const evaluation = JSON.parse(res.data.evaluation.evaluation)


        this.Attendance = evaluation.Attendance
        this.Pronunciation = evaluation.Pronunciation
        this.Grammar = evaluation.Grammar
        this.Comprehension = evaluation.Comprehension
        this.Fluency = evaluation.Fluency
        this.PronunciationComment = evaluation.PronunciationComment
        this.GrammarComment = evaluation.GrammarComment
        this.ComprehensionComment = evaluation.ComprehensionComment
        this.FluencyComment = evaluation.FluencyComment
        this.TeachersNote = evaluation.TeachersNote
        this.date = evaluation.date

        this.Level = res.data.class['schedule']['Level']


        this.Curriculum = res.data.class['schedule']['Curriculum']

          this.onChangeCurriculum(this.Curriculum)

              this.Material  = res.data.class['schedule']['Material']








        console.log(evaluation, 'eval')


    }

    this.$set(this.$data, 'Tutor', res.data.tutor)
    this.$set(this.$data, 'Class', res.data.class)





    this.showMenu()



    console.log(res.data, 'data')
  })
},

methods: {

  showMenu() {

    if (!this.isMenuShowing) {
      this.leftColumn = 6
      this.rightColumn = 6
      this.rightStyle = ''
      this.isMenuShowing = true
      this.arrow = 'arrow_right'
    } else {
      this.leftColumn = 12
      this.rightColumn = 0
      this.rightStyle = 'display:none'
      this.isMenuShowing = false
      this.arrow = 'arrow_left'
    }
  },


  onChangeCurriculum(event) {
    if (event == 'Freetalking') {
      vue.set(this.$data, 'books', [])
    } else if (event == 'Introductory Course') {
      vue.set(this.$data, 'books', this.$data.book_introductory_course)
    } else if (event == 'Elementary/Intermediate Conversation Course') {
      vue.set(this.$data, 'books', this.$data.book_elementary_course)
    } else if (event == 'Regular Conversation') {
      vue.set(this.$data, 'books', this.$data.book_regular_conversation)
    } else if (event == 'New York Live English') {
      vue.set(this.$data, 'books', [])
    } else if (event == 'Grammar Pattern Course') {
      vue.set(this.$data, 'books', this.$data.book_grammar_pattern)
    } else if (event == 'Beginner Discussion') {
      vue.set(this.$data, 'books', this.$data.book_beginner_discussion)
    } else if (event == 'Business Course') {
      vue.set(this.$data, 'books', this.$data.book_business_course)
    } else if (event == 'Specialized Job Preparation Course') {
      vue.set(this.$data, 'books', this.$data.book_specialize_job_preparation_course)
    } else if (event == 'Discussion/Free Talking Course') {
      vue.set(this.$data, 'books', this.$data.book_discussion_course)
    }
  },


  getEndContract(){


  let class_end_schedule = this.Class['schedule']['class_end'].split(",")

  let end_schedule =  class_end_schedule[class_end_schedule.length-1]

  return end_schedule.split(" ")[0]




},

getApplicableDays(){

  return this.Class['schedule']['applicable_days'].substr(0,this.Class['schedule']['applicable_days'].length -1 ).substr(1)
},

getHour(){

  return moment({hour: this.Class['schedule']['hour'], minute:this.Class['schedule']['minute']}).format('HH:mm:ss')


},

addLevelTestEvaluation(){


const studentname = this.Class['schedule']['name']
const tutorname = this.Tutor['mega_name']
const tutoridx = this.Tutor['idx']
const classid =  this.Class['schedule']['classid']
const phone_number = this.Class['schedule']['phone_number']
const preference_number = this.Class['schedule']['preference_number']








const Evaluation = {  Attendance: this.Attendance,  Pronunciation: this.Pronunciation, Grammar: this.Grammar, Comprehension: this.Comprehension, Fluency: this.Fluency,  PronunciationComment: this.PronunciationComment, GrammarComment: this.GrammarComment, ComprehensionComment: this.ComprehensionComment, FluencyComment: this.FluencyComment , TeachersNote: this.TeachersNote, date: moment().format('YYYY-MM-DD'), tutorName: tutorname, tutorIdx: tutoridx, classid: classid, Level: this.Level, Curriculum: this.Curriculum, Material: this.Material, preference_number: preference_number}



const checkObj =  Object.values(Evaluation).some(data => (data === null || data === ''))




if(checkObj === true || !this.Level || !this.Curriculum || !this.Material || !studentname || !classid ){

  this.EvaluationError = true
  this.$vuetify.goTo(0)
}

else{
const form = new FormData()
form.append('evaluation', JSON.stringify(Evaluation))
form.append('Level', this.Level)
form.append('Curriculum', this.Curriculum)
form.append('Material', this.Material)
form.append('studentname', studentname)
form.append('classid', classid)
form.append('phone_number', phone_number)
form.append('preference_number', preference_number)


axios.post('Evaluation/addLevelTestEvaluation', form).then(res => {

  if(res.data.error === false){

    window.close()
  }



  console.log(res.data, 'data')
}).catch(err => {

  console.log(err, 'err')
})

}



}



},
}
</script>

<style lang="css">
</style>
