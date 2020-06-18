<template style="overflow-x: hidden;">
<v-container fluid >



<div class="d-flex flex-row justify-space-between">
	<v-row justify="center">

		<v-col xs="12" sm="12" md="3" class="pr-0" >
			<v-date-picker v-model="date2" @change = "getDailyClasses()" :event-color="'red'" :events="Schedules" :max-width="pickerWidth"></v-date-picker>
		</v-col>

		<v-col xs="12" sm="12" md="6" class="pl-0">
			<v-card class="eventCard" height="100%" :style="styleClass">

				<v-card class="pa-0 ma-0 eventCard" color="#1976d2" height="24%" flat>
					<v-container>
						<v-row align="center" class="pl-4 mt-4" >
							<span class="white--text font-weight-medium display-1">My Classes</span>
						</v-row>
					</v-container>
				</v-card>

				<v-card flat>
				<v-container class="">
					<v-expansion-panels tile flat>
						<v-expansion-panel v-for="(item,i) in Tutors" :key="i">
							<v-expansion-panel-header v-if = "checkSchedule(item['schedule'])">
								<div class="d-flex flex-row">
									<v-icon color="blue lighten-4" class="mr-2">fiber_manual_record</v-icon>
									<span class="mt-1" style = "text-transform:capitalize;">{{item['tutor']['mega_name']}}</span>
									<v-spacer></v-spacer>
									<span class="mt-1 mr-5" v-if = "checkStatus(item['schedule'])">{{getSchedule(item['schedule'])}}</span>
									<span class="mt-1 mr-5" v-else>Cancelled</span>
								</div>
							</v-expansion-panel-header>
							<v-expansion-panel-content  v-if = "checkStatus(item['schedule'])">
								<v-row>
									<v-icon class="mx-2" color="#1976d2" medium @click = "joinMeeting(item['tutor']['conn_id'], item['schedule']['classid'])">videocam</v-icon>
									<v-icon class="mx-2" color="#1976d2" medium>book</v-icon>
									<v-icon class="mx-2" color="#1976d2" medium  @click = "showEvaluations(item['schedule']['classid'], item['schedule'])">description</v-icon>
									<v-icon class="mx-2" color="#1976d2" medium>headset</v-icon>
									<v-icon class="mx-2" color="#1976d2" medium  v-if = "checkFunction(item['schedule'])">insert_chart</v-icon>
									<v-spacer></v-spacer>
									<v-icon class="mx-2" color="#1976d2" medium v-if = "checkFunction(item['schedule'])">edit</v-icon>
									<v-icon class="mx-2" color="#1976d2" medium @click = "openChat(item)" v-if = "checkFunction(item['schedule'])">chat</v-icon>
									<v-icon class="mx-2" color="#1976d2" medium v-if = "checkFunction(item['schedule'])">loop</v-icon>
									<v-icon class="mx-2" color="#1976d2" medium v-if = "checkFunction(item['schedule'])">event_busy</v-icon>
								</v-row>
							</v-expansion-panel-content>
						</v-expansion-panel>
					</v-expansion-panels>
				</v-container>
				</v-card>

			</v-card>
		</v-col>
	</v-row>


  <div class="float-right button-container" >
    <div class="buttons">
        <v-row class="ma-2 mb-4">
          <button class="float-right ml-2 v-btn v-btn--depressed theme--light" style="background-color:#1976d2" icon>
            <v-icon color="white" x-large>add</v-icon>
          </button>
        </v-row>
        <v-row class="ma-2 mb-4">
          <button class="float-right ml-2 v-btn v-btn--depressed theme--light" style="background-color:#1976d2" icon>
            <v-icon color="white" x-large>question_answer</v-icon>
          </button>
        </v-row>
      </div>
  </div>

  </div>

	<div class = "features">

		<v-dialog v-model="evaluationDialog" max-width="1000">
			<v-card>
				<v-container>
					<v-row>
						<v-col cols="12" md="6" >
							<p class="text-center display-1">Scores</p>
							<div style="position:relative">
								<div style="position:absolute;width:48%;z-index:5;">
									<p class="text-right mb-0" style="color:#7c868e">Pronunciation</p>
									<p class="text-right mb-0 pt-2" style="color:#7c868e">Grammar</p>
									<p class="text-right mb-0 pt-1" style="color:#7c868e">Comprehension</p>
									<p class="text-right mb-0 pt-1" style="color:#7c868e">Fluency</p>
								</div>

								<div class="text-center">
		 							<v-progress-circular :value="selectedEvaluation['Pronunciation'] * 10" width="25" size="350" color="#64b5f6" rotate="-90">
											<v-progress-circular :value="selectedEvaluation['Grammar'] * 10" width="25" size="290" color="#1976d2" rotate="-90">
												<v-progress-circular :value="selectedEvaluation['Comprehension'] * 10" width="25" size="230" color="#ef6c00" rotate="-90">
													<v-progress-circular :value="selectedEvaluation['Pronunciation'] * 10" width="25" size="170" color="#ffd54f" rotate="-90">
													</v-progress-circular>
												</v-progress-circular>
											</v-progress-circular>
		 							</v-progress-circular>
								</div>
							</div>
						</v-col>
						<v-col cols="12" md="6">
							<p class="text-center display-1">Today's Class</p>
							<v-row>
								<v-col cols="12" class="py-0">{{selectedEvaluation['Material']}}</v-col>
							</v-row>
							<v-row>
								<v-col cols="12" class="py-0">{{selectedEvaluation['Lesson']}}</v-col>
							</v-row>
							<v-row>
								<v-col cols="12" class="py-0">{{selectedEvaluation['pageNumber']}}</v-col>
							</v-row>
							<v-row class="mt-2">
								<v-col cols="12">
									<v-card color="#6bbde9" flat max-width="100">
										<v-card-text class="white--text text-center pa-1" >Sentences</v-card-text>
									</v-card>
								</v-col>
							</v-row>
							<v-row>
								<v-col cols="12" class="py-0">1. {{selectedEvaluation['Corrected1']}}</v-col>
							</v-row>
							<v-row>
								<v-col cols="12" class="py-0">2. {{selectedEvaluation['Corrected2']}}</v-col>
							</v-row>
							<v-row class="mt-2">
								<v-col cols="12">
									<v-card color="#6bbde9" flat max-width="150">
										<v-card-text class="white--text text-center pa-1" >Words of the Day</v-card-text>
									</v-card>
								</v-col>
							</v-row>
							<v-row>
								<v-col cols="12" class="py-0">1. {{selectedEvaluation['word1']}}{{selectedEvaluation['transcript1']}}</v-col>
							</v-row>
							<v-row class="mb-2">
								<v-col cols="12" class="py-0"> {{selectedEvaluation['definition1']}}/{{selectedEvaluation['example1']}}/{{selectedEvaluation['synonyms1']}}</v-col>
							</v-row>
							<v-row>
								<v-col cols="12" class="py-0">2. {{selectedEvaluation['word1']}}{{selectedEvaluation['transcript1']}}</v-col>
							</v-row>
							<v-row class="mb-4">
								<v-col cols="12" class="py-0 mb-2">{{selectedEvaluation['definition1']}}/{{selectedEvaluation['example1']}}/{{selectedEvaluation['synonyms1']}}</v-col>
							</v-row>
							<v-row>
								<v-col cols="12" class="py-0">Teacher {{selectedEvaluation['tutorName']}}</v-col>
							</v-row>
							<v-row class="d-flex justify-content-end">
								<v-btn class="mr-2" outlined>Close</v-btn>
							</v-row>
						</v-col>
					</v-row>
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
						  <v-row :class = "message.sender_conn_id !== selectedTutor ? 'justify-end' :  '' " >



	          <v-list flat 	:color = "message.sender_conn_id !== selectedTutor ? 'primary' : 'grey'" >


	        <v-list-item >
	          <v-list-item-icon v-if = "message.sender_conn_id === selectedTutor">
	            <v-avatar color="red">
	        <span class="white--text" >{{message.message.charAt(0).toUpperCase()}}</span>
	      </v-avatar>
	          </v-list-item-icon>
	          <v-list-item-content>
	            <div>{{message.message}}  </div>
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




</v-container>
</template>

<script>

import moment from 'moment'

import axios from 'axios'
export default {

	data: () => ({
		Messages: [],
		chatDialog: false,
		selectedTutor: '',
		Tutor: '',
		message: '',
		selectedEvaluation: '',
		Tutors: [],
		evaluationDialog: false,
		Schedules: [],
		arrayEvents: null,
		date2: new Date().toISOString().substr(0, 10),
		styleClass: '',
		pickerWidth:'',
	}),



	mounted() {


		this.arrayEvents = [...Array(6)].map(() => {
			const day = Math.floor(Math.random() * 30)
			const d = new Date()
			d.setDate(day)
			return d.toISOString().substr(0, 10)
		})




		console.log(this.$vuetify.breakpoint.name)

		if(this.$vuetify.breakpoint.name == "xs"){
			this.styleClass = "margin-left:12px;"
			this.pickerWidth = "360"
		}

		console.log(this.date2, 'date')

		this.getDailyClasses()





	},

	methods: {
		functionEvents(date) {
			const [, , day] = date.split('-')
			if ([12, 17, 28].includes(parseInt(day, 10))) return true
			if ([1, 19, 22].includes(parseInt(day, 10))) return ['red', '#00f']
			return false
		},

		async getClasses(){

			await axios.get('Student/getClasses').then(res => {

				if(res.data.tutors){

					this.$set(this.$data, 'Tutors', res.data.tutors)
				}
				console.log(this.Tutors, 'classes')
			})
		},

			async getDailyClasses(){


				if(this.date2){

					const date = this.date2

					const day = moment(this.date2, "YYYY-MM_DD").day()

					const week = day === 1 ? 'M' : day === 2  ? 'T' : day === 3  ? 'W' : day === 4  ? 'TH' : day === 5  ? 'F' : ''



					const form = new FormData()

					form.append('setDate', date)
					form.append('setWeekDay', week)


				await	axios.post('Student/getDailyClasses', form).then(res => {

						console.log('testTUtoes', res.data)

						this.$set(this.$data, 'Tutors', res.data.tutors)



						if(this.Tutors){

						const schedules = this.Tutors.map(data => data.schedule).map(data => data.class_start)[0].substring(1).slice(0, -1).split(",").forEach((item, i) => {



						this.Schedules.push(item.split(' ')[0])

						});






					}

						console.log(this.Schedules, 'week')

					})

				}
			},

		getSchedule(schedule){



			let start = moment({hour: schedule['hour'], minute: schedule['minute']}).format('HH:mm:ss')

			let end = moment(start,'HH:mm:ss').add(parseInt(schedule['duration']), 'minutes').format('HH:mm:ss')

			return start + " - " + end
		},

		checkSchedule(schedule){

			 const date2 = this.date2 + ' '


			if(schedule){

				if(schedule['cancelled'] === true && schedule['makeUpDate'] !== date2){

					return false
				}



return true

}
		},

		checkStatus(schedule){


if(schedule['cancelled_class']){
			let date = this.date2
			let start_time = moment({hour: schedule['hour'], minute:schedule['minute']}).format('HH:mm:ss')
			let end_time = moment(start_time, 'HH:mm:ss').add(parseInt(schedule['duration']), 'minutes').format('HH:mm:ss')

			let start_date = date + ' ' + start_time
			let end_date  = date + ' ' + end_time


			let start_time_search = schedule['cancelled_class'].includes(start_date)
			let end_time_search = schedule['cancelled_class'].includes(end_date)
			if(start_time_search && end_time_search){

				return false
			}
}

return true


		},


		checkFunction(schedule){

			console.log(schedule, 'ss')

			const date2 = this.date2 + ' '


		 if(schedule){

		 	if(schedule['cancelled'] === true && schedule['makeUpDate'] === date2){

		 		return false
		 	}



		 return true

		 }

		},

		showEvaluations(classid, classinfo){



if(classid){

	const form = new FormData()

	form.append('classid', classid)
			axios.post('Evaluation/get_student_evaluations', form).then( res => {




				const evaluation = res.data

				if(evaluation){
					this.selectedEvaluation = evaluation
					this.selectedEvaluation.definition1 =   this.selectedEvaluation.definition1 ? JSON.parse(this.selectedEvaluation.definition1) : ''
					this.selectedEvaluation.definition2 =   this.selectedEvaluation.definition2 ? JSON.parse(this.selectedEvaluation.definition2) : ''
					this.selectedEvaluation.example1 =   this.selectedEvaluation.example1 ? JSON.parse(this.selectedEvaluation.example1) : ''
					this.selectedEvaluation.example2 =   this.selectedEvaluation.example2 ? JSON.parse(this.selectedEvaluation.example2) : ''
					this.selectedEvaluation.Material = classinfo.bookMaterial


						this.evaluationDialog = true

						console.log(this.selectedEvaluation)
				}

			})


		}
	},

	openChat(item){

this.Tutor = item['tutor']
this.selectedTutor = item['tutor']['conn_id']

this.getMessage();

this.chatDialog = true


},

	sendMessage(){

	if(this.message.trim() && this.selectedTutor){


		const message = this.message
		const receiver_conn_id = this.selectedTutor


		const form = new FormData()
		form.append('message', message)
		form.append('receiver_conn_id', receiver_conn_id)


		axios.post('Chat/createMessage', form).then(res => {

			if(res.data.error === false){

				console.log(res.data.message, 'msg')

				this.Messages.push(res.data.message)



			}

			console.log(res.data, 'res')
		})

		this.message = ''
	}
},

async getMessage(){

	const receiver_conn_id = this.selectedTutor

	if(receiver_conn_id){

		const form = new FormData()

		form.append('receiver_conn_id', receiver_conn_id)

		await axios.post('Chat/getMessage', form).then(res => {

			if(res.data){


				const parse = JSON.parse(res.data)

parse.forEach((item, i) => {

parse[i] = JSON.parse(item)
});


				this.$set(this.$data, 'Messages', parse)



				console.log(this.Messages, 'tez')


			}


		})
	}

},

joinMeeting(tutor, classSchedule){

	if(tutor && classSchedule){

		    window.open('http://localhost/lms/#/StudentZoom/' + tutor + '/' + classSchedule, '_blank');
	}


}

	},

	sockets: {

	  chat_message(data){
	    if(data){
	      const message = JSON.parse(data)
				console.log(message, 'nnn')
				console.log(this.selectedTutor, 'nn')

				if(message.sender_name === this.Tutor.mega_name){
	    this.Messages.push(message)

	  }
}
	  }
	}




}
</script>

<style scoped lang="css">

  .eventCard{
    border-radius: 0px;
  }

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
