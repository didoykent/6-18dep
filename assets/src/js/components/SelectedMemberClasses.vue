<template>

  <v-container>
    <v-overlay :value="availableTutorLoading">
      <v-progress-circular indeterminate size="64"></v-progress-circular>
    </v-overlay>

    <v-row>

      <v-col sm="12">

        <v-card  style="width: 99.3%;" height = "100%">
          <v-card-title v-if = "Tutor && tutorClasses.length">


          {{Tutor['mega_name']}} Classes
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

                                    <tr v-for="(item, index) in tutorClasses" >

                                        <td style="border-left: 0px;">{{index + 1}}</td>
                                        <td>Ready</td>
                                        <td>{{getTime(item['schedule'].hour, item['schedule'].minute, item['schedule'].duration)}}</td>
                                        <td>
                                          <v-icon left color="blue"  v-if = "item['schedule'].class_type === 'Video Zoom'">mdi-video</v-icon>
                                          <v-icon left color="blue"  v-if = "item['schedule'].class_type === 'Phone'">mdi-phone</v-icon>
                                          <v-icon left color="blue" v-if = "item['schedule'].class_type === 'Video Skype'">mdi-skype</v-icon>
                                        </td>
                                        <td>{{item['schedule'].name}}</td>
                                        <td>{{item['schedule'].academy}}</td>
                                        <td>{{item['schedule'].phone_number}}</td>
                                          <td>{{item['schedule'].bookMaterial}}</td>

                                        <td><v-icon left color="green">mdi-clipboard-text</v-icon></td>

                                        <td class="py-2">
                                          <div class="d-flex">


                                            <button  v-if = "item['TO']"class="ml-2 v-btn v-btn--depressed theme--light" style="background-color:#E91E63" icon>
                                              <v-icon color="#F8BBD0" @click="cancel_take_over(item)">backspace</v-icon>
                                            </button>

                                          </div>
                                        </td>
                                    </tr>
                                </tbody>
        </template>




        </v-data-table>
      </v-card>

       </v-col>
    </v-row>

    <v-dialog v-model="cancel_take_over_dialog" persistent max-width="900" max-height="500">


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
                          <td>{{selectedClass['schedule']['classid']}}</td>
                          <td>{{selectedClass['schedule']['applicable_days']}}</td>
                          <td>{{getSchedule(selectedClass)}}</td>
                          <td>{{selectedClass['schedule']['duration']}} minutes</td>
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
          <v-btn class="mr-2" @click="cancel">Cancel</v-btn>
          <v-btn class="mr-3" color="primary" @click="cancel_take_over_selected()" small>Apply Changes</v-btn>
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

      tutorClasses: [],
      selectedTutor: '',
      selectedClass: '',
      cancel_take_over_dialog: false,
      changeTeacherVerify: false,
      		date: new Date().toISOString().substr(0, 10),
          	menu: false,
      TutorsAvailable: [],
      availableTutorLoading: false,
      Tutor: '',
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
        { text: 'Actions'}
      ],

    }
  },
  computed: {
  	computedDateFormatted() {
  		return this.formatDate(this.date)
  	},
  },

  mounted(){

    const idx = this.$route.params.idx

    const form = new FormData()

    form.append('memberIdx', idx )

    axios.post('Tutor/get_all_classes_by_tutor', form).then(res => {

      console.log(res.data)
      if(res.data){

        this.$set(this.$data, 'Tutor', res.data.tutor)
        this.$set(this.$data, 'tutorClasses', res.data.tutorClasses)
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

    getSchedule(currentClass){

      return moment({hour:currentClass['schedule']['hour'], minute:currentClass['schedule']['minute']}).format('HH:mm:ss')
    },
    cancel(){

      location.reload()
    },

    cancel_take_over(studentclass){
      this.selectedClass = studentclass
      this.availableTutorLoading = true
      console.log(studentclass['schedule'], 'test')

      const form = new FormData()


      form.append('start_class', studentclass['schedule']['class_start'])
      form.append('end_class', studentclass['schedule']['class_end'])
      form.append('weekdays', JSON.parse(studentclass['schedule']['applicable_days']))
      form.append('tutor', this.Tutor['idx'])

      axios.post('Tutor/changeTeacher', form).then(res => {

        console.log(res.data, 'teacher')

        if (res.data) {

          this.$set(this.$data, 'TutorsAvailable', res.data)

          let checkData = setInterval(() => {

            if (this.TutorsAvailable) {
              this.availableTutorLoading = false;
              this.changeTeacherVerify = true
              this.changeTeacherSameTime = true
              this.cancel_take_over_dialog = true
              clearInterval(checkData)
            }
          }, 1000)
        }
        else{

            clearInterval(checkData)
        }

      })

    },

  cancel_take_over_selected(){
             const form = new FormData()

    form.append('tutoridx', this.Tutor['idx'])

    form.append('classData', JSON.stringify(this.selectedClass['schedule']))


    form.append('selectedTutorIdx', this.selectedTutor['idx'])


             axios.post('Tutor/cancel_take_over_selected', form).then(res => {

               if (res.data.success1 && res.data.success2) {

                 location.reload()
               }
               console.log(res.data, 'res')
             })
  }



  }


}
</script>

<style lang="css" scoped>
</style>
