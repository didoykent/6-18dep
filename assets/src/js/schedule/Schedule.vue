<template>
<div>
  <v-container >
    <v-layout column  >
    <v-row >

      <v-col sm="3" >

     <v-date-picker  full-width  @change = "getStudentsSchedule() "v-model="picker"></v-date-picker>
      </v-col>

      <v-col  sm="9" >


        <v-card    style="width: 99.3%;"  height = "100%">
    <v-card-title v-if = "Schedule.length > 0">


    <span style="text-transform: capitalize">{{Tutor['mega_name']}}'s </span>  <span style="text-indent: 0.2em;"> Schedule</span>
      <v-spacer></v-spacer>

    </v-card-title>

    <v-card-title v-else>


    No Data Available
      <v-spacer></v-spacer>

    </v-card-title>


    <v-data-table
      :headers="headers"
            :hide-default-footer = "true"

    >


<template v-slot:body  >

  <tbody >

<tr v-for = "schedule in Schedule"  >

  <td  style="border-left: 0px; ">{{schedule[0]}}</td>
  <template v-for = "(item, index) in schedule">

    <td @click = "getEvaluation(schedule[index+1])">

  <template v-if="getIndex(schedule[index+1])">
      <v-chip

            :color="getColor(schedule[index+1])"



        >
            <v-avatar left>
              <v-icon color = "blue">{{getIcon(schedule[index+1])}}</v-icon>
            </v-avatar>
          {{getIndex(schedule[index+1]).name}}
          </v-chip>

        </template>

    </td>
  </template>

</tr>


  </tbody>

</template>



    </v-data-table>

  </v-card>

</v-col>





</v-row  >


<v-row >

  <v-col sm = "3">
    <v-simple-table>
        <template v-slot:default>
          <thead>
            <tr>
              <th class="text-left">Phone</th>
              <th class="text-right">Video</th>
            </tr>
          </thead>
          <tbody>
            <tr>
          <th class="text-right" style="background-color:#C5E1A5; width:50%;">Free</th>
          <th class="text-left" style="background-color:#9CCC65;">Class</th>
            </tr>

            <tr>
          <th class="text-right" style="background-color:#E3F2FD;">Regular</th>
          <th class="text-left" style="background-color:#BBDEFB;">Class</th>
            </tr>

            <tr>
          <th class="text-right" style="background-color:#FFCCBC;">Makeup</th>
          <th class="text-left" style="background-color:#FFAB91;">Class</th>
            </tr>
          </tbody>
        </template>
      </v-simple-table>

      <br>

      <v-simple-table   class="elevation-1">
          <template v-slot:default>
            <thead>

                  <th class="text-center" style="background-color: #F8BBD0;">Month-end Speaking Test</th>

            </thead>

            <thead>

                  <th class="text-center" style="background-color: #FFE082;">No Substitute Teacher</th>

            </thead>

            <thead>

                  <th class="text-center" style="background-color: #B39DDB;">Reserved</th>

            </thead>

          </template>
        </v-simple-table>

  </v-col>

  <v-col sm="9">

    <v-card  style="width: 99.3%;" height = "100%">
      <v-card-title v-if = "Schedule.length > 0">


        Student Details
        <v-spacer></v-spacer>

      </v-card-title>

      <v-card-title v-else>


      No Data Available
        <v-spacer></v-spacer>

      </v-card-title>
    <v-data-table
      :headers="headers2"
      no-data-text
      :hide-default-footer = "true"

    >



    <template v-slot:body>

      <tbody>

                                <tr v-for="(item, index) in studentDetails" :key="item.id">

                                    <td style="border-left: 0px;">{{index + 1}}</td>
                                    <td>{{getStatus(item[0], index)}}</td>
                                    <td>{{getTime(item[0].hour, item[0].minute, item[0].duration)}}</td>
                                    <td>
                                      <v-icon left color="blue"  v-if = "item[0].class_type === 'Video Zoom'" @click = "zoom_credentials(item[0])">mdi-video</v-icon>
                                      <v-icon left color="blue"  v-if = "item[0].class_type === 'Phone'">mdi-phone</v-icon>
                                      <v-icon left color="blue" v-if = "item[0].class_type === 'Video Skype'">mdi-skype</v-icon>
                                    </td>
                                    <td>{{item[0].name}}</td>
                                    <td>{{item[0].academy}}</td>
                                    <td>{{item[0].phone_number}}</td>
                                      <td>{{item[0].bookMaterial}}</td>
                                    <td><v-icon left color="green">mdi-clipboard-text</v-icon></td>


                                </tr>
                            </tbody>
    </template>




    </v-data-table>
  </v-card>

   </v-col>
</v-row>

<v-row>


</v-row>
</v-layout>
</v-container>

<v-dialog v-model="zoom_credentials_dialog" persistent max-width="600px">

     <v-card>
       <v-card-title>
         <span class="headline">Zoom Credentials</span>
       </v-card-title>
       <v-card-text>
         <v-container>
           <v-row>

             <v-col cols="12">
               <v-text-field label="Meeting Id*" v-model = "zoom.MeetingId" required></v-text-field>
             </v-col>
             <v-col cols="12">
               <v-text-field label="Meeting Password*"  v-model = "zoom.MeetingPassword" required></v-text-field>
             </v-col>

           </v-row>
         </v-container>
         <small>*indicates required field</small>
       </v-card-text>
       <v-card-actions>
         <v-spacer></v-spacer>
         <v-btn color="blue darken-1" text @click="zoom_credentials_dialog = false">Close</v-btn>
         <v-btn color="blue darken-1" text @click="check_zoom_room()">Save</v-btn>
       </v-card-actions>
     </v-card>
   </v-dialog>

</div>
</template>

<script>

import axios from 'axios'
import moment from 'moment'
  export default {
    data () {
      return {
        zoom: [],
        selectedClass: {},
        zoom_credentials_dialog: false,
         picker: new Date().toISOString().substr(0, 10),
         Tutor: '',
        Schedule: [],
        tutorSchedule: [],
        studentDetails:[],

        search: '',
        headers: [
          { text: 'Time', value: 'name'},
          { text: '00', value: 'name'},
          { text: '10', value: 'name'},
          { text: '20', value: 'name'},
          { text: '30', value: 'name'},
          { text: '40', value: 'name' },
          { text: '50', value: 'name' },

        ],



       headers2: [
         {
           text: 'No',
           align: 'left',
           sortable: true,
           value: 'no',
         },
         { text: 'Status', value: 'status' },
         { text: 'Time', value: 'time' },
        { text: '', value: 'classtype' },
         { text: 'Name', value: 'name' },
         { text: 'Account', value: 'account' },
         { text: 'Contact', value: 'contact' },
         { text: 'Material', value: 'material' },
         { text: 'Review', value: 'lastclass' },
       ],






      }
    },

    mounted(){

this.getStudentsSchedule()



    },

    methods: {

      getColor(classType){

        console.log(classType, 'color')

          if(classType['makeUpDate']){

            if(classType['makeUpDate'] && classType['class_type'] === 'Phone' ){

              return 'deep-orange lighten-4'
            }

            if(classType['makeUpDate'] && classType['class_type'] === 'Video' ){

              return 'deep-orange lighten-3'
            }
          }

        if(classType['class_type'] === 'Phone'){

          return 'blue lighten-5'
        }

        if(classType['class_type'] === 'Video Skype' || classType['class_type'] === 'Video Zoom' ){

          return 'blue lighten-4'
        }

      },

      getIcon(item){


          if(item['class_type'] === 'Video Zoom'){

            return 'mdi-video'
          }

          if(item['class_type'] === 'Phone'){

            return 'mdi-phone'
          }

          if(item['class_type'] === 'Video Skype'){

            return 'mdi-skype'
          }

      },

      getTime(hour, minute, duration){

        if( hour <= 9){
          hour = '0' + hour
        }
        if(minute <= 9){
          minute = '0' + minute
        }
          let time  =  hour +  ':' + minute

          return time + '+' + duration
      },

      getStatus(item, index){
            console.log(item, 'itemm')


        if(item){

          if(item['isCancelled']){

            return 'Cancelled'

        }

        if(item['makeUpDate']){

          return 'MC'
        }
        else{

          return 'Ready'
        }
        }


      },




      getStudentsSchedule(){
this.$set(this.$data, 'Schedule', [])


const currentDate = this.picker

const form = new FormData()

form.append('currentDate', currentDate)


console.log(currentDate, 'ccurr')
const token = localStorage.getItem('token')
axios.post('tutor/getClassSchedule', form).then(res => {

console.log(res.data, 'sched')

let start = parseInt(res.data.tutor.start_am)
let end = parseInt(res.data.tutor.end_pm)

let class_schedule = JSON.parse(res.data.class_schedule)



let tutorSchedule = []

for(var i = start; i<=end; i++){

    tutorSchedule.push(i)
}

        this.tutorSchedule = tutorSchedule

let class_schedule_lists = []


for(var i =0; i<class_schedule.length; i++){
  let index = class_schedule_lists.findIndex(data => data.hour === class_schedule[i]['schedule']['hour'])

if(index ){

  class_schedule_lists.push(class_schedule[i].schedule)
}

}



for(var i =0; i<tutorSchedule.length; i++){

let data = class_schedule_lists.filter(schedule => parseInt(schedule.hour) === parseInt(tutorSchedule[i]))

if(data.length){


this.Schedule.push(data)


}

}



for(var i =0; i<this.Schedule.length; i++){

this.Schedule[i].sort((a, b) => a.minute - b.minute);
}





for(var i =0; i<this.Schedule.length; i++){

this.Schedule[i].unshift(this.Schedule[i][0].hour)

var sched = this.Schedule[i]

for(var s =1; s<sched.length; s++){

console.log(this.Schedule, 'wow')


if(this.Schedule[i][s]){
if(this.Schedule[i][s].minute === 0){




this.Schedule[i].splice(s, 0, this.Schedule[i].splice(1, 1)[0])








}

}
if(this.Schedule[i][s]){
if(this.Schedule[i][s].minute === 10){

this.Schedule[i].splice(s, 0, this.Schedule[i].splice(2, 1)[0])




}
}
if(this.Schedule[i][s]){
if(this.Schedule[i][s].minute === 20){

this.Schedule[i].splice(s, 0, this.Schedule[i].splice(3, 1)[0])



}
}

if(this.Schedule[i][s]){

if(this.Schedule[i][s].minute === 30){

  this.Schedule[i].splice(s, 0, this.Schedule[i].splice(4, 1)[0])




}
}

if(this.Schedule[i][s]){

if(this.Schedule[i][s].minute === 40){

  this.Schedule[i].splice(s, 0, this.Schedule[i].splice(5, 1)[0])




}


}

if(this.Schedule[i][s]){

if(this.Schedule[i][s].minute === 50){

  this.Schedule[i].splice(s, 0, this.Schedule[i].splice(6, 1)[0])




}
}







}


}

for(var i = 0; i<this.Schedule.length; i++){

var sched = 6 - this.Schedule[i].length


for(var s = 0; s<sched; s++){

this.Schedule[i].push('')
}


}







console.log(this.Schedule, 'what')








console.log(this.tutorSchedule)





})
this.getStudentDetails()

      },


      getStudentDetails(){


        this.$set(this.$data, 'studentDetails', [])

        const currentDate = this.picker

        const form = new FormData()

        form.append('currentDate', currentDate)


  console.log(currentDate, 'ccurr')
      const token = localStorage.getItem('token')
      axios.post('tutor/getClassSchedule', form).then(res => {

        console.log(res.data, 'sched')

        let start = parseInt(res.data.tutor.start_am)
        let end = parseInt(res.data.tutor.end_pm)

        let class_schedule = JSON.parse(res.data.class_schedule)



        let tutorSchedule = []

        for(var i = start; i<=end; i++){

            tutorSchedule.push(i)
        }

                this.tutorSchedule = tutorSchedule

        let class_schedule_lists = []


        for(var i =0; i<class_schedule.length; i++){

          class_schedule[i]['schedule']['cancelled_class'] = class_schedule[i]['cancelled_class']
          if(  class_schedule[i]['schedule']['cancelled_class']){
          let currentSchedule =   class_schedule[i]['schedule']

          let date = this.picker
          let start_time = moment({hour: currentSchedule['hour'], minute:currentSchedule['minute']}).format('HH:mm:ss')
          let end_time = moment(start_time, 'HH:mm:ss').add(parseInt(currentSchedule['duration']), 'minutes').format('HH:mm:ss')

          let start_date = date + ' ' + start_time
          let end_date  = date + ' ' + end_time


          let start_time_search = currentSchedule['cancelled_class'].includes(start_date)
          let end_time_search = currentSchedule['cancelled_class'].includes(end_date)

          if(start_time_search === true && end_time_search === true){

            class_schedule[i]['schedule']['isCancelled'] = true
          }
    }
          class_schedule_lists.push(class_schedule[i].schedule)

        }



    for(var i =0; i<tutorSchedule.length; i++){

let data = class_schedule_lists.filter(schedule => parseInt(schedule.hour) === parseInt(tutorSchedule[i]))

  if(data.length){

  this.studentDetails.push(data)
  }

    }



  for(var i =0; i<this.studentDetails.length; i++){

   this.studentDetails[i].sort((a, b) => a.minute - b.minute);
  }


console.log(this.studentDetails, 'details')
})

},




      test(){

        let schedule = new Date("2015-03-25:07:30:00");

        var number = '5'
        var minute = '5'

        let num = moment(number,"LT").format('HH')
        let min = moment(minute,"LT").format('HH')

        var mom = moment(num+min, 'HHmmss').format('HH:mm:ss')

        let date  = '2015-03-25' + ':'



        let stringdate =  date + mom

        console.log(stringdate)




    },

    getIndex(item){

        console.log(item, 'index')
if(item){

      return item

    }

    if(item === undefined){


    }


  },

  getEvaluation(item){

    console.log(item, 'it')

    const classid = item['classid']

    if(item['category'] === 'regularclass'){

    window.open('http://localhost/lms/#/MemberStudentEvaluation2/' + classid, '_blank');
  }

    if(item['category'] === 'leveltest'){

    window.open('http://localhost/lms/#/LevelTestStudentEvaluation2/' + classid, '_blank');
    }
  },

  zoom_credentials(item){

    this.selectedClass = item

    this.zoom.MeetingId = this.selectedClass['meetingId'];
    this.zoom.MeetingPassword = this.selectedClass['meetingPw'];


    this.zoom_credentials_dialog = true
  },


check_zoom_room(){

  if(this.zoom.MeetingId && this.zoom.MeetingPassword && this.selectedClass){
    const classid = this.selectedClass['classid']

    const meetingId = this.zoom.MeetingId
    const meetingPassword = this.zoom.MeetingPassword

    const form = new FormData()

    form.append('meetingId', meetingId)
    form.append('meetingPw', meetingPassword)
    form.append('classId', classid)

    axios.post('Tutor/check_zoom_room', form).then(res => {

      if(res.data.success){

          location.reload()
      }

      console.log(res.data)
    }).catch(err => {


      console.log(err, 'err')
    })



    console.log(this.selectedClass, 'zoomcre')
  }


}



  }
}
</script>

<style scoped>



 td{
   border:1px solid #e0e0e0;
 }





</style>
