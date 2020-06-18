<template>
  <v-container fluid>

    <v-overlay :value="availableTutorLoading">
      <v-progress-circular indeterminate size="64"></v-progress-circular>
    </v-overlay>

    <v-row>
      <v-col cols="12" sm="10" md="3" class="pb-0 mr-2">
        <v-text-field outlined label="Search" v-model="search" append-icon="search"></v-text-field>
      </v-col>
    </v-row>
    <v-row>
      <v-col cols="12" sm="12" md="12" class="pb-0">
        <v-data-table :headers="headers"  class="elevation-1" :search="search">
          <template v-slot:body>
            <tbody v-for = "(item, index) in Students">
                <tr>
                  <td><span class="red--text">New</span></td>
                  <td>{{item['academy']}}</td>
                  <td>{{item['class_type']}}</td>
                  <td>{{item['classid']}}</td>
                  <td @click = "changeName()" style="text-decoration: underline;">{{item['name']}}</td>
                  <td @click = "changeNumber()" style="text-decoration: underline;">{{item['phone_number']}}</td>
                  <td>{{item['skypeid']}}</td>
                  <td style="text-decoration: underline;" @click  = "changeSchedule(item)">{{item['date']}}</td>
                  <td>{{getTime(item)}}</td>
                  <td>{{item['duration']}}</td>
                  <td style="text-decoration: underline;" @click = "changeTeacher(item)">{{item['tutor_name']}}</td>
                  <td>Ready</td>
                </tr>
            </tbody>
          </template>
        </v-data-table>
      </v-col>
    </v-row>


    <v-dialog v-model="changeScheduleModal" persistent max-width="900" max-height="500">

      <v-card class="pa-4">
        <v-card-title class="headline" style="background-color:#E0E0E0;">Change Schedule</v-card-title>
        <v-row align="center">
          <v-col cols="5">
            <v-card class="mb-2 mt-4">
              <v-row>
                <v-container>
                  <v-simple-table>
                    <template v-slot:default>
                      <thead>
                        <tr>
                          <th>Class ID</th>
                          <th>Days</th>
                          <th>Schedule</th>
                          <th>Duration</th>
                        </tr>
                      </thead>
                      <tbody>
                        <tr>
                          <td>{{currentStudent['classid']}}</td>
                          <td>{{currentStudent['applicable_days']}}</td>
                          <td>{{getTime(currentStudent)}}</td>
                          <td>{{currentStudent['duration']}} minutes</td>
                        </tr>
                      </tbody>
                    </template>
                  </v-simple-table>
                </v-container>
              </v-row>
            </v-card>
          </v-col>

          <v-col cols="7">
            <v-alert color="warning" elevation="5" class="white--text">
              <center> Please fill all the fields required to select your desired schedule.</center>

            </v-alert>
          </v-col>
        </v-row>

        <v-row>
          <v-col cols="4" class="pt-0">
            <v-menu v-model="menu" :close-on-content-click="false" transition="scale-transition" offset-y full-width max-width="290px" min-width="290px">
              <template v-slot:activator="{ on }">
                <v-text-field outlined v-model="computedDateFormatted" label="Start Date" placeholder="MM/DD/YYYY format" v-on="on"></v-text-field>
              </template>
              <v-date-picker    v-model="date" no-title @input="menu = false"></v-date-picker>
            </v-menu>
          </v-col>
          <v-col cols="4" class="pt-0" align="center">
            <v-select :items="hours"  @change = "checkTimeData()" v-model  ="hour" label="Hour" outlined></v-select>
          </v-col>
          <v-col cols="4">
            <v-btn color="success" :disabled = "TimeData" @click="outgoingTeacherAvailable()">Check Available Teacher</v-btn>
          </v-col>
        </v-row>

        <v-row>

          <v-col cols="4" class="pt-0" align="center">
            <v-select :items="minutes"  @change = "checkTimeData()" v-model = "minute" label="Minute" outlined></v-select>
          </v-col>
        </v-row>

        <v-row class="mb-4 mx-1" >
          <v-expansion-panels>
            <v-expansion-panel v-for="(Tutor, index) in TutorsAvailable" :key="index">
              <v-expansion-panel-header>
                <v-checkbox  @change = "checkSelectedTutor" v-model="selectedTutor" :value="Tutor" :label="Tutor.mega_name" />
                <template v-slot:actions v-if="Tutor.warning">
                  <span>
                    <v-icon color="error">mdi-alert-circle</v-icon>
                    Warning
                  </span>
                </template>
              </v-expansion-panel-header>
              <v-expansion-panel-content>
                Information of Tutor
                <br>
                Specialty : {{Tutor.specialty}}
                <br>
                Major: {{Tutor.major}}
              </v-expansion-panel-content>
            </v-expansion-panel>
          </v-expansion-panels>
        </v-row>

        <v-row>
          <v-col cols="12" class="pt-0">
            <v-textarea outlined label="Reason"></v-textarea>
          </v-col>
        </v-row>


        <v-row>
          <v-spacer></v-spacer>
          <v-btn class="mr-2" @click = "changeScheduleModal = false" small >Cancel</v-btn>
          <v-btn class="mr-3" color="primary" :disabled="!isSelected" @click="changeOutgoingSchedule()" small>Apply Changes</v-btn>
        </v-row>


      </v-card>
    </v-dialog>



    <v-dialog v-model="changeTeacherModal" persistent max-width="900" max-height="500">

      <v-card class="pa-4">
        <v-card-title class="headline" style="background-color:#E0E0E0;">Change Teacher</v-card-title>
        <v-row align="center">
          <v-col cols="5">
            <v-card class="mb-2 mt-4">
              <v-row>
                <v-container>
                  <v-simple-table>
                    <template v-slot:default>
                      <thead>
                        <tr>
                          <th>Class ID</th>
                          <th>Days</th>
                          <th>Schedule</th>
                          <th>Duration</th>
                        </tr>
                      </thead>
                      <tbody>
                        <tr>
                          <td>{{currentStudent['classid']}}</td>
                          <td>{{currentStudent['applicable_days']}}</td>
                          <td>{{getSchedule()}}</td>
                          <td>{{currentStudent['duration']}} minutes</td>
                        </tr>
                      </tbody>
                    </template>
                  </v-simple-table>
                </v-container>
              </v-row>
            </v-card>
          </v-col>

          <v-col cols="7">
            <v-alert color="warning" elevation="5" class="white--text">
              <center> We found another teacher for you. Please choose whom you think would be the best one for you.</center>
            </v-alert>
          </v-col>
        </v-row>

        <v-row>
          <v-col cols="4" class="pt-0">
            <v-menu v-model="menu" :close-on-content-click="false" transition="scale-transition" offset-y full-width max-width="290px" min-width="290px">
              <template v-slot:activator="{ on }">
                <v-text-field outlined :disabled="true" v-model="computedDateFormatted" label="Start Date" placeholder="MM/DD/YYYY format" v-on="on"></v-text-field>
              </template>
              <v-date-picker :disabled="true" v-model="date" no-title @input="menu = false"></v-date-picker>
            </v-menu>
          </v-col>

        </v-row>

        <v-row class="mb-4 mx-1" v-if="changeTeacherVerify">
          <v-expansion-panels>
            <v-expansion-panel v-for="(Tutor, index) in TutorsAvailable" :key="index">
              <v-expansion-panel-header>
                <v-checkbox v-model="selectedTutor" :value="Tutor" :label="Tutor.mega_name" />
                <template v-slot:actions v-if="Tutor.warning">
                  <span>
                    <v-icon color="error">mdi-alert-circle</v-icon>
                    Warning
                  </span>
                </template>
              </v-expansion-panel-header>
              <v-expansion-panel-content>
                Information of Tutor
                <br>
                Specialty : {{Tutor.specialty}}
                <br>
                Major: {{Tutor.major}}
              </v-expansion-panel-content>
            </v-expansion-panel>
          </v-expansion-panels>
        </v-row>

        <v-row>
          <v-col cols="12" class="pt-0">
            <v-textarea outlined label="Reason"></v-textarea>
          </v-col>
        </v-row>


        <v-row>
          <v-spacer></v-spacer>
          <v-btn class="mr-2" @click="changeTeacherModal = false" small>Cancel</v-btn>
          <v-btn class="mr-3" color="primary" @click="changeTeacherSelected(studentclass)" small>Apply Changes</v-btn>
        </v-row>

      </v-card>
    </v-dialog>
  </v-container>
</template>

<script>

import moment from 'moment'

import axios from 'axios'
export default {

  data(){
    return{
      changeTeacherModal: false,

      availableTutorLoading: false,
      selectedTutor: '',
      isSelected: false,
      TutorsAvailable: [],
      TimeData: true,
      minute: '',
      hour: '',
      minutes: ['00','10','20','30','40','50'],
      hours: [6, 7 ,8 ,9 ,10 ,11 ,12, 13, 14 ,15 ,16 ,17 ,18 ,19 ,20 ,21 ,22 ,23],
      changeScheduleModal: false,
        date: new Date().toISOString().substr(0, 10),
        dateFormatted: this.formatDate(new Date().toISOString().substr(0, 10)),
      currentStudent: [],
        Students: [],
        changeTimeVerifyTeacher: false,
      headers: [{
    			text: '',
    			align: 'left',
    			value: '',
    		},
        {
  				text: 'Academy',
  				align: 'left',
  				value: 'academy',
  			},
  			{
  				text: 'Class Type',
          sortable: false,
  				value: 'class_type'
  			},
  			{
  				text: 'Class ID',
          sortable: false,
  				value: 'claass_id'
  			},
  			{
  				text: 'Student Name',
          sortable: false,
  				value: 'student_name'
  			},
        {
  				text: 'Phone Number',
          sortable: false,
  				value: 'phone_number'
  			},
        {
  				text: 'Skype ID',
          sortable: false,
  				value: 'skype_id'
  			},
        {
  				text: 'Level Test Date',
  				value: 'test_date'
  			},
        {
  				text: 'Time',
  				value: 'time'
  			},
        {
  				text: 'Duration(min)',
          sortable: false,
  				value: 'duration'
  			},
        {
  				text: 'Teacher',
  				value: 'teacher'
  			},
        {
  				text: 'Status',
  				value: 'status'
  			},
  		],



    }
  },

  mounted(){

    axios.get('Tutor/getLevelTestStudents').then(res => {

      this.$set(this.$data, 'Students', res.data)



      console.log(this.Students, 'data')
    })
  },

  watch: {
  	date(val) {
  		this.dateFormatted = this.formatDate(this.date)
    }
  	},

  computed: {
  	computedDateFormatted() {
  		return this.formatDate(this.date)
  	}
  },

  methods:{

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


      getTime(item){

        return moment({hour:item.hour, minute: item.minute}).format('HH:mm:ss')
      },

      getMin() {



        return moment().format('YYYY-MM-dd')


      },




      changeTeacher(item){

        this.currentStudent = item

        this.availableTutorLoading = true
        console.log(this.currentStudent, 'test')

        const form = new FormData()


        form.append('start_class', this.currentStudent['class_start'])
        form.append('end_class', this.currentStudent['class_end'])
        form.append('weekdays', JSON.parse(this.currentStudent['applicable_days']))
        form.append('tutor', this.currentStudent['tutor_idx'])

        axios.post('Tutor/changeTeacher', form).then(res => {

          console.log(res.data, 'teacher')

          if (res.data) {

            this.$set(this.$data, 'TutorsAvailable', res.data)

            let checkData = setInterval(() => {

              if (this.TutorsAvailable) {
                this.availableTutorLoading = false;
                this.changeTeacherVerify = true

                this.changeTeacherModal = true
                clearInterval(checkData)
              }
            }, 1000)
          }
})

      },


       changeTeacherSelected(){

         const form = new FormData()




         form.append('tutoridx', this.currentStudent['tutor_idx'])

         form.append('classData', JSON.stringify(this.currentStudent))


         form.append('selectedTutorIdx', this.selectedTutor['idx'])


         axios.post('Tutor/outGoingTeacherSelected', form).then(res => {

           if (res.data.success1 && res.data.success2) {

             location.reload()
           }
           console.log(res.data, 'res')
         })

       },

      changeSchedule(item){

        this.currentStudent = item

        this.changeScheduleModal = true

      },

      changeName(){


      },

      changeNumber(){


      },


      outgoingTeacherAvailable(){

        let weekdays = this.currentStudent['applicable_days']

        let current_date = this.currentStudent['class_start'].split(" ")[0]

        let start_time = moment({hour: this.hour, minute:this.minute}).format('HH:mm:ss')

        let end_time = moment(start_time, 'HH:mm:ss').add(this.currentStudent['duration'], 'minutes').format('HH:mm:ss')

        let start_date = current_date + ' ' + start_time

        let end_date = current_date  + ' ' + end_time

        console.log(start_date, 'date')
        console.log(end_date , 'end')


      const form = new FormData()

      form.append('start_class',  start_date)
      form.append('end_class',  end_date)
      form.append('weekdays', weekdays)



      axios.post('Tutor/outgoingTeacherAvailable', form).then(res => {

        if(res.data){
        this.$set(this.$data, 'TutorsAvailable', res.data)

}


        console.log(res.data)
      })


    },


    checkTimeData(){

      if(this.hour && this.minute){

        this.TimeData = false
      }
    },

    checkSelectedTutor(){

      if(this.selectedTutor){

        this.isSelected = true
      }

      else{

        this.isSelected = false
      }
    },

    changeOutgoingSchedule(){

      let weekdays = this.currentStudent['applicable_days']

      let current_date = this.currentStudent['class_start'].split(" ")[0]

      let start_time = moment({hour: this.hour, minute:this.minute}).format('HH:mm:ss')

      let end_time = moment(start_time, 'HH:mm:ss').add(this.currentStudent['duration'], 'minutes').format('HH:mm:ss')

      let start_date = current_date + ' ' + start_time

      let end_date = current_date  + ' ' + end_time


      this.currentStudent['class_start'] = start_date
      this.currentStudent['class_end'] = end_date




    const form = new FormData()

    form.append('tutoridx', this.currentStudent['tutor_idx'])

    form.append('classData', JSON.stringify(this.currentStudent))

    form.append('selectedTutorIdx', this.selectedTutor['idx'])

    axios.post('Tutor/changeOutgoingSchedule', form).then(res =>{

      if (res.data.success1 && res.data.success2) {

        location.reload()
      }

      console.log(res.data, 'sched')
    })


},

getSchedule(){



return  moment({hour: this.currentStudent['hour'], minute: this.currentStudent['minute']}).format('HH:mm:ss')

}











  }


}
</script>

<style lang="css">

.link{
  text-decoration: none;
}

.router-link{
background:blue;
}

.nav{
max-width: 200px;
}

</style>
