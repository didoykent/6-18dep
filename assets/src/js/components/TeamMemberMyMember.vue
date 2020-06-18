<template>
  <v-container fluid style="height:100%">
    <v-card style="height:100%">
      <v-card flat>
        <v-card-title>Team {{teamLeader['team']}}</v-card-title>

        <v-data-table class="mr-3" :headers="headers">
          <template v-slot:body>
            <tbody v-for = "(member, index) in teamMembers">
              <tr>
                <td>{{index+1}}</td>
                <td>{{member['mega_name']}}</td>
                <td>{{member['position']}}</td>
                <td>{{member['start_am']}}</td>
                <td>5:51</td>
                <td>{{member['end_am']}}</td>
                <td>Present</td>
                <td>{{member['start_pm']}}</td>
                <td>14:50</td>
                <td>{{member['end_pm']}}</td>
                <td>Present</td>
                <td>{{member['starting_date']}}</td>
                <td class="py-2">
                  <div class="d-flex">
                    <button  @click= "viewTutorData(member)"class="ml-2 v-btn v-btn--depressed theme--light" style="background-color:#E91E63" icon>
                      <v-icon color="#F8BBD0">account_circle</v-icon>
                    </button>
                    <button  @click = "memberViewClasses(member)"class="ml-2 v-btn v-btn--depressed theme--light" style="background-color:#E91E63" icon>
                      <v-icon color="#F8BBD0">date_range</v-icon>
                    </button>
                    <button class="ml-2 v-btn v-btn--depressed theme--light" style="background-color:#E91E63" icon>
                      <v-icon color="#F8BBD0" @click="setTakeOver(member)">event_busy</v-icon>
                    </button>
                    <button class="ml-2 v-btn v-btn--depressed theme--light" style="background-color:#E91E63" icon>
                      <v-icon color="#F8BBD0">assessment</v-icon>
                    </button>
                  </div>
                </td>
              </tr>
            </tbody>
          </template>
        </v-data-table>

      </v-card>

<!--  dialog -->
      <v-dialog v-model="takeOverDialog" max-width="1000" max-height="500">
        <v-card>
          <v-card-title class="headline" style="background-color:#E0E0E0;">Take Over</v-card-title>
          <v-container style="background-color:#FFF">
            <v-row>
              <v-card flat tile>
                <v-data-table class="mr-3" :headers="headers1">
                  <template v-slot:body>
                    <tbody>
                      <tr>
                        <td>1</td>
                        <td>{{selectedMember['mega_name']}}</td>
                        <td>{{selectedMember['position']}}</td>
                        <td>{{selectedMember['start_am']}}</td>
                        <td>5:51</td>
                        <td>{{selectedMember['end_am']}}</td>
                        <td>Present</td>
                        <td>{{selectedMember['start_pm']}}</td>
                        <td>14:50</td>
                        <td>{{selectedMember['end_pm']}}</td>
                        <td>Present</td>
                        <td>{{selectedMember['starting_date']}}</td>
                      </tr>
                    </tbody>
                  </template>
                </v-data-table>
              </v-card>
            </v-row>
            <v-row class="px-2" align="center">
              <span class="mb-2 ml-3">Date</span>
              <v-col cols="12" md="3" class="pb-0 mr-md-4">
                <v-menu v-model="menu" :close-on-content-click="false" transition="scale-transition" offset-y full-width max-width="290px" min-width="290px">
                  <template v-slot:activator="{ on }">
                    <v-text-field outlined v-model="computedDateFormatted" label="Date" placeholder="MM/DD/YYYY format" v-on="on"></v-text-field>
                  </template>
                  <v-date-picker :min = "getMin()" v-model="date" no-title @input="menu = false"></v-date-picker>
                </v-menu>
              </v-col>
              <span class="mb-2">Time</span>
              <v-col cols="12" md="2" class="pb-0">
                <v-select  v-model = "startHour" label="Start" :items="timeStarts"outlined></v-select>
              </v-col>
              <span class="mb-2">to</span>
              <v-col cols="12" md="2" class="pb-0 mr-md-4">
                <v-select  v-model = "endHour" label="End"  :items="timeEnds"outlined></v-select>
              </v-col>
              <v-col class="" align-items="center" cols="12" md="2">
                <v-btn class="white--text" color="#e91e63" @click="getclassLists()">List Classes</v-btn>
              </v-col>
            </v-row>
            <v-row v-if="listClass">
              <v-card flat tile style="width: 100%">
                <v-simple-table class="mr-3">
                  <template v-slot:default>
                      <tr>
                        <th>#</th>
                        <th>Status</th>
                        <th>Time</th>
                        <th>Name</th>
                        <th>Account</th>
                        <th>Material</th>
                        <th>Take Over</th>
                        <th>Teacher</th>
                      </tr>
                    <tbody v-for = "(studentclass, index) in classLists" :key="index">
                      <tr>
                        <td>1</td>
                        <td>Ready</td>
                        <td>{{getTimeSchedule(studentclass)}} + {{studentclass['duration']}}</td>
                        <td>{{studentclass['name']}}</td>
                        <td>{{studentclass['account']}}</td>
                        <td>{{studentclass['material']}}</td>
                        <td><v-btn color="#e91e63" class="white--text" @click = "takeOverAvailable(studentclass, index)">Set</v-btn></td>
                        <td><v-select  v-model = "selectedTutor[index]" @change="selectedClass(studentclass, index)" class="mb-0"  outlined :items="getItems(index)" item-text="mega_name"  item-value="idx"></v-select></td>
                      </tr>
                    </tbody>
                  </template>
                </v-simple-table>
              </v-card>
            </v-row>
            <v-row v-if="listClass">
              <v-col cols="12" md="4">
                <v-select :items="reasons" outlined label="Reason"></v-select>
              </v-col>
              <v-col cols="12" md="8">
                <v-text-field placeholder="Details" outlined></v-text-field>
              </v-col>


            </v-row>
            <v-row justify = "end">
              <v-col align="end">
              <v-btn color="#e91e63"  @click = "cancel()" class="white--text">Cancel</v-btn>


                <v-btn color="#e91e63" @click = "apply()" class="white--text">Apply Changes</v-btn>
                </v-col>
            </v-row>
          </v-container>
        </v-card>
      </v-dialog>
<!--  dialog -->


      <v-spacer></v-spacer>

      <v-card flat>
        <v-card-title>Monitoring</v-card-title>
        <v-data-table :headers="headers">
          <template v-slot:body>
            <tbody v-for = "(tutor, index) in teamMonitoring">
              <tr>

                  <td>{{index+1}}</td>
                  <td>{{tutor['mega_name']}}</td>
                  <td>{{tutor['position']}}</td>
                  <td>{{tutor['start_am']}}</td>
                  <td>5:51</td>
                  <td>{{tutor['end_am']}}</td>
                  <td>Present</td>
                  <td>{{tutor['start_pm']}}</td>
                  <td>14:50</td>
                  <td>{{tutor['end_pm']}}</td>
                  <td>Present</td>
                  <td>{{tutor['starting_date']}}</td>

                <td class="py-2">
                  <div class="d-flex">
                    <button class="ml-2 v-btn v-btn--depressed theme--light" style="background-color:#E91E63" icon>
                      <v-icon color="#F8BBD0">account_circle</v-icon>
                    </button>
                    <button class="ml-2 v-btn v-btn--depressed theme--light" style="background-color:#E91E63" icon>
                      <v-icon color="#F8BBD0">date_range</v-icon>
                    </button>
                    <button  @click="setTakeOver(tutor)"class="ml-2 v-btn v-btn--depressed theme--light" style="background-color:#E91E63" icon>
                      <v-icon color="#F8BBD0">event_busy</v-icon>
                    </button>
                  </div>
                </td>
              </tr>
            </tbody>
          </template>
        </v-data-table>
        <v-container fluid>
          <v-row justify="end">
            <v-col cols="2" align-self="end" class="d-flex justify-content-end">
              <v-btn color="#e91e63" class="white--text" @click = "addMonitoring()">Add Team Member</v-btn>
            </v-col>
          </v-row>
        </v-container>
      </v-card>
    </v-card>

    <!--  Add monitoring dialog -->
    <v-row justify="center">
    <v-dialog v-model="addMonitoringDialog" persistent max-width="600px">

      <v-card>
        <v-card-title>
          <span class="headline">Add monitoring tutor</span>
        </v-card-title>
        <v-card-text>
          <v-container>
            <v-row>

              <v-col cols="12" sm="6">
                <v-select
                  disabled

                  :items="Tutors"
                  label="Select Tutor"
                  item-text="mega_name"
                   item-value="idx"
                    v-model = "monitoringSelectedTutor"

                  required
                ></v-select>
              </v-col>

            </v-row>
          </v-container>

        </v-card-text>
        <v-card-actions>
          <v-spacer></v-spacer>
          <v-btn color="blue darken-1" text @click="addMonitoringDialog = false">Close</v-btn>
          <v-btn color="blue darken-1" text @click="saveMonitoring()">Save</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </v-row>

  <v-dialog v-model="memberEditDialog" max-width="1000" min-height="750">
    <v-card class="px-4 pb-4">
      <v-card-title class="headline">
        <div class="d-flex justify-content-center align-items-center mr-2" style="height:50px;width:50px;
        background-color:#e91e63;">
        <v-icon color="white" x-large>account_circle</v-icon>
      </div>
      Member Information
    </v-card-title>
    <v-container>

      <v-row class="title">
        Personal Information
      </v-row>

      <v-row class="pb-0">
        <v-col cols="12" sm="6" md="3" class="pb-0">
          <v-text-field   disabled class="pb-0" label="Mega Name" v-model="editTutor.mega_name" placeholder="Mega Name"></v-text-field>
        </v-col>
        <v-col cols="12" sm="6" md="3" class="pb-0">
          <v-text-field   disabled class="pb-0" label="Position" v-model="editTutor.position" placeholder="Position"></v-text-field>
        </v-col>
        <v-col cols="12" sm="6" md="3" class="pb-0">
          <v-text-field   disabled class="pb-0" label="First Name" v-model="editTutor.first_name" placeholder="First Name"></v-text-field>
        </v-col>
        <v-col cols="12" sm="6" md="3" class="pb-0">
          <v-text-field   disabled class="pb-0" label="Last Name" v-model="editTutor.last_name" placeholder="Last Name"></v-text-field>
        </v-col>
      </v-row>

      <v-row class="py-0">
        <v-col cols="12" sm="6" md="3" class="personal py-0">
          <v-text-field   disabled label="Sex" v-model="editTutor.sex" placeholder="Sex"></v-text-field>
        </v-col>
        <v-col cols="12" sm="6" md="3" class="personal py-0">
          <v-text-field   disabled label="Date of Birth" v-model="editTutor.date_of_birth" placeholder="Date of Birth"></v-text-field>
        </v-col>
        <v-col cols="12" sm="6" md="3" class="personal py-0">
          <v-text-field   disabled label="Mobile Number" v-model="editTutor.mobile_number" placeholder="Mobile Number"></v-text-field>
        </v-col>
        <v-col cols="12" sm="6" md="3" class="personal py-0">
          <v-text-field   disabled label="Email" :rules='emailRules' v-model="editTutor.email" placeholder="Email"></v-text-field>
        </v-col>
      </v-row>

      <v-row class="py-0">
        <v-col cols="12" lg="12" class="py-0">
          <v-text-field   disabled label="Residential Address" v-model="editTutor.address" placeholder="Residential Address"></v-text-field>
        </v-col>
      </v-row>

      <v-row class="py-0 mb-5">
        <v-col cols="12" md="6" class="py-0">
          <v-text-field   disabled label="Major" v-model="editTutor.major" placeholder="Major"></v-text-field>
        </v-col>
        <v-col cols="12" md="6" class="py-0">
          <v-text-field   disabled label="School" v-model="editTutor.school" placeholder="School"></v-text-field>
        </v-col>
      </v-row>

      <v-row class="title">
        Work Experience
      </v-row>

      <v-row class="pb-0">

        <template v-for="(work, index) in editTutor['workexp']">
          <v-col cols="12" sm="6" md="3" class="pb-0">
            <v-text-field   disabled label="Position" v-model="editTutor['workexp'][index]['Position']" placeholder="Position"></v-text-field>
          </v-col>
          <v-col cols="12" sm="6" md="3" class="pb-0">
            <v-text-field   disabled label="Company Name" v-model="editTutor['workexp'][index]['Company']"placeholder="Company Name"></v-text-field>
          </v-col>
          <v-col cols="12" sm="6" md="3" class="pb-0">
            <v-text-field   disabled label="From" v-model="editTutor['workexp'][index]['Start date']" placeholder="From"></v-text-field>
          </v-col>
          <v-col cols="12" sm="6" md="3" class="pb-0">
            <v-text-field   disabled label="To"  v-model="editTutor['workexp'][index]['End date']"placeholder="To"></v-text-field>
          </v-col>

        </template>
      </v-row>







      <v-row class="title mb-4">
        Introduction
      </v-row>

      <v-row>
        <v-col cols="12" md="12" class="py-0">
          <v-textarea   disabled name="input-7-4" label="Introduction" v-model="editTutor.introduction" placeholder="Introduce yourself as a teacher here"></v-textarea>
        </v-col>
      </v-row>
      <v-row>
        <v-col cols="12" sm="12" class="pb-0">
          <v-text-field   disabled label="Specialty" v-model="editTutor.specialty" placeholder="Specialty"></v-text-field>
        </v-col>
      </v-row>

      <v-row>
        <v-spacer></v-spacer>
        <div class="my-2">
          <v-btn color="#E91E63" @click = "close()"class="white--text">Close</v-btn>
        </div>

      </v-row>

    </v-container>
  </v-card>
</v-dialog>
  </v-container>
</template>

<script>
import SelectedMemberClasses from './SelectedMemberClasses.vue'
import axios from 'axios'
import moment from 'moment'
export default {

  components: {SelectedMemberClasses},


  data() {

    return {


      teamLeader: '',
      addMonitoringDialog: false,
      monitoringSelectedTutor: '',
      currentIndex: '',
      selectedClasses: [],
      teamMembers: [],
      Tutors: [],
      editTutor: [],
      memberEditDialog: false,
      tutorsAvailable: [],
      selectedTutor: [],
      classLists: [],
      selectedMember: [],
      timeStarts: [],
      startHour: '',
      endHour: '',
      timeEnds: [],
      teamMonitoring: [],
      date: new Date().toISOString().substr(0, 10),
      dateFormatted: this.formatDate(new Date().toISOString().substr(0, 10)),
      menu: false,
      takeOverDialog: false,
      listClass: false,

      reasons: ['Unexcused Absence', 'Tardy', 'Undertime', 'Vacation Leave', 'Sick Leave', 'Emergency Leave'],
      headers: [{
        text: '#',
        align: 'left',
        value: '',
      },
      {
        text: 'Mega Name',
        align: 'left',
        value: 'name',
      },
      {
        text: 'Position',
        align: 'left',
        value: 'position'
      },
      {
        text: 'AM SOS',
        align: 'left',
        value: 'am_sos'
      },
      {
        text: 'AM Login',
        value: 'am_log'
      },
      {
        text: 'AM EOS',

        value: 'am_eos'
      },
      {
        text: 'AM Attendance',
        value: 'am_attendance'
      },
      {
        text: 'PM SOS',
        value: 'pm_sos'
      },
      {
        text: 'PM Login',
        value: 'pm_log'
      },
      {
        text: 'PM EOS',

        value: 'pm_eos'
      },
      {
        text: 'PM Attendance',
        value: 'pm_attendance'
      },
      {
        text: 'Hire Date',

        value: 'duration'
      },
      {
        text: 'Actions',
        align: 'center',
        sortable: false,
        value: 'actions'
      },
    ],

    headers1: [{
      text: '#',
      align: 'left',
      value: '',
    },
    {
      text: 'Mega Name',
      align: 'left',
      value: 'name',
    },
    {
      text: 'Position',
      align: 'left',
      value: 'position'
    },
    {
      text: 'AM SOS',
      align: 'left',
      value: 'am_sos'
    },
    {
      text: 'AM Login',
      value: 'am_log'
    },
    {
      text: 'AM EOS',

      value: 'am_eos'
    },
    {
      text: 'AM Attendance',
      value: 'am_attendance'
    },
    {
      text: 'PM SOS',
      value: 'pm_sos'
    },
    {
      text: 'PM Login',
      value: 'pm_log'
    },
    {
      text: 'PM EOS',
      value: 'pm_eos'
    },
    {
      text: 'PM Attendance',
      value: 'pm_attendance'
    },
    {
      text: 'Hire Date',
      value: 'duration'
    },
  ],




}
},

mounted(){

  axios.get('Tutor/getTeamMembers').then(res => {

    console.log(res.data, 'data')

    if(res.data){

      this.$set(this.$data, 'teamMembers', res.data.teamMembers)
      this.$set(this.$data, 'teamMonitoring', res.data.teamMonitoring)
      this.$set(this.$data, 'Tutors', res.data.Tutors)

      this.$set(this.$data, 'teamLeader', res.data.teamLeader)
    }
  })

},

methods: {
  formatDate(date) {
    if (!date) return null

    const [year, month, day] = date.split('-')
    return `${month}/${day}/${year}`
  },
  parseDate(date) {
    if (!date) return null

    const [month, day, year] = date.split('/')
    return `${year}-${month.padStart(2, '0')}-${day.padStart(2, '0')}`
  },

  getMin(){

 return moment().format('YYYY-MM-DD')
},

setTakeOver(member){

  this.selectedMember = member
  console.log(this.selectedMember, 'selected')
  if(this.selectedMember){


    let start = parseInt(  this.selectedMember.start_am)
    let end = parseInt(  this.selectedMember.end_pm)





    for(var i = start; i<=end; i++){

        this.timeStarts.push(i)
        this.timeEnds.push(i)
    }


    if(this.timeStarts && this.timeEnds){

        this.takeOverDialog = true
    }
}
},

getclassLists(){

  let start = this.startHour
  let end = this.endHour
  let date = this.date

  let hourRange = []
    for(var i = start; i<end; i++){

        hourRange.push(i)
    }

    if(hourRange && date ){

      const form = new FormData()

      form.append('hourRange', hourRange)
      form.append('selectedDate', date)
      form.append('selectedMember', this.selectedMember['idx'])

      axios.post('Tutor/getClassLists', form).then(res => {
        if(res.data.success){
          this.$set(this.$data, 'classLists', res.data.classes)
            this.listClass = true

              console.log(this.classLists, 'asdada')
        }
        else{
          this.listClass = false
            this.classLists = []
        }

        console.log(res.data , 'classlists')
      })
    }
},


getTimeSchedule(studentclass){


  return moment({hour: studentclass['hour'], minute: studentclass['minute']}).format('HH:mm')
},

takeOverAvailable(studentclass,index){

  const start_class = studentclass['class_start']
  const end_class = studentclass['class_end']
  const applicable_days = studentclass['schedule']['applicable_days']

  const form = new FormData()

  form.append('start_class', start_class)
  form.append('end_class', end_class)
  form.append('weekdays', applicable_days)

  axios.post('Tutor/get_take_over_available', form).then(res => {

    console.log(res.data, 'sadad')
    if(res.data){

      this.currentIndex = index
      console.log(index , 'sada')



   this.tutorsAvailable[parseInt(index)]  =  res.data

   this.getclassLists()

      console.log(this.tutorsAvailable, 'sadsa')


    }
  })


},


getItems(index){




   console.log(this.tutorsAvailable[parseInt(index)], 'data')


  return this.tutorsAvailable[parseInt(index)]

},

selectedClass(studentclass, index){
  if(this.selectedTutor[index]){

    this.selectedClasses[parseInt(index)] = {schedule: studentclass['schedule'], selectedTutor: this.selectedTutor[index], currentTutor: this.selectedMember['idx']}
  }

console.log(this.selectedClasses, 'clazzes')
},





checkTutor(){

  console.log(this.selectedTutor, 'asda')
},

cancel(){

  location.reload()
},

apply(){
if(this.selectedClasses){


let weekdays  = ''
let date = this.date

if(moment(date).format('dddd') === 'Monday'){

	weekdays = 'M'
}
if(moment(date).format('dddd') === 'Tuesday'){

	weekdays = 'T'
}

if(moment(date).format('dddd') === 'Wednesday'){

	weekdays = 'W'
}

if(moment(date).format('dddd') === 'Thursday'){

	weekdays = 'TH'
}

if(moment(date).format('dddd') === 'Friday'){

	weekdays = 'F'
}


let selectedDate = this.date + ' '

let selectedClasses = this.selectedClasses
let rearrange = [];
selectedClasses.forEach((selectedClasses, i) => {



let start = moment({hour: selectedClasses['schedule']['hour'], minute: selectedClasses['schedule']['minute']}).format('HH:mm:ss')
let end = moment(start, 'HH:mm:s s').add(parseInt(selectedClasses['schedule']['duration']), 'minutes').format('HH:mm:ss')

  selectedClasses['schedule']['class_start'] = selectedDate + start
  selectedClasses['schedule']['class_end'] = selectedDate + end
  selectedClasses['schedule']['applicable_days'] = weekdays

  rearrange.push(selectedClasses)

});





const form = new FormData()

form.append('selectedClasses', JSON.stringify(rearrange))

axios.post('Tutor/set_take_over', form).then(res => {

  if(res.data.success){

    location.reload()
  }
})



}
},

addMonitoring(){

  this.addMonitoringDialog = true
},

 saveMonitoring(){


let selectedTutor = this.monitoringSelectedTutor


const form = new FormData();

form.append('selectedTutor', selectedTutor)
axios.post('Tutor/saveMonitoring', form).then(res => {

  if(res.data.success){

    location.reload()
  }

  console.log(res.data, 'selected')
})


},

memberViewClasses(member){
const idx = member['idx']
  this.$router.push('/MemberViewClasses/' + idx)
},

viewTutorData(member){

  this.editTutor = member

  if(this.editTutor){



    this.memberEditDialog = true

    let parse = JSON.parse(this.editTutor.workexp)
    let workexp = parse.split(',')

    let extractData = []

    workexp.forEach((item, i) => {


      let companySearch = item.search('Company')
      let start_date_search = item.search('Start date')
      let end_date_search = item.search('End date')

      let position = item.substring( companySearch-1, 0)
      let company = item.substring(companySearch, start_date_search-1)
      let start_date = item.substring( start_date_search, end_date_search-1)
      let end_date = item.substring( end_date_search, item.length)

          extractData.push({'Position': position.split(": ")[1], 'Company': company.split(": ")[1], 'Start date': start_date.split(": ")[1], 'End date': end_date.split(": ")[1]})
    });


this.editTutor.workexp = extractData
console.log(extractData, 'extract')

  }
},

close(){
    this.memberEditDialog = false
}
},

computed: {
  computedDateFormatted() {
    return this.formatDate(this.date)
  },




},

watch: {
  date(val) {
    this.dateFormatted = this.formatDate(this.date)
  },
},
}
</script>

<style>

.v-data-footer{
  display: none;
}

.v-text-field__details{
  display: none;
}


</style>
