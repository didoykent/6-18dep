<template>
<v-container>

	<v-row>
		<v-col cols="12" sm="12" md="3" class="pb-0 ml-2">
			<v-select :items="academies" label="Academy" outlined></v-select>
		</v-col>
		<v-col cols="12" sm="12" md="3" class="pb-0">
			<v-select :items="types" label="Type" outlined></v-select>
		</v-col>
		<v-spacer></v-spacer>
		<v-col cols="12" sm="10" md="3" class="pb-0 mr-2">
			<v-text-field outlined label="Search" v-model="search" append-icon="search"></v-text-field>
		</v-col>

	</v-row>

	<v-row>
		<v-col cols="12" sm="12" md="12" class="pb-0">
			<v-data-table :headers="headers"  class="elevation-1" :search="search">
				<template v-slot:body>
					<tbody>
							<tr v-for = "(item, index) in Students">

								<td>{{item['academy']}}</td>
								<td>{{item['class_type']}}</td>

								<td>{{item['id']}}</td>



								<td>
									<v-icon class="px-2" medium color="#e91e63" @click="editClass($event, item)">edit</v-icon>
									<v-icon class="px-2" color="#e91e63">add_circle</v-icon>
									<v-icon class="px-2" color="#e91e63">headset</v-icon>
								</td>

							</tr>
					</tbody>
				</template>
			</v-data-table>
		</v-col>
	</v-row>
</v-container>
</v-row>

</v-container>
</template>

<script>

import moment from 'moment'
import axios from 'axios'
export default {



	data: vm => ({
		tab: null,

		Classes: [],

		Tutor: [],

		Tutors: [],

		Students: [],


		academies: ['All Academies', 'Alton Study', 'Anytalk', 'Bigcat', 'Daily Speaking', 'ECK Edu', 'Edunuri', 'Engforu', 'EnglishTOK', 'EverydayCN', 'Flocampus',
			'Future', 'G Talking', 'GG Youth', 'Grace Talk', 'Himsolutek', 'Injae', 'JKOLS', 'JoongAng', 'JoongAng China', 'JTalk',
			'Kakyo Edu', 'Kingdom Edu', 'Kisan', 'LangTalk', 'LG Academy', 'Making Speaker',
			'Mangolang', 'Megatalking', 'MGEnglish', 'Mirae', 'MK Edu', 'Mot English',
			'Narae', 'Phonetalk', 'SayOn', 'SGS', 'SKN(Kwak)', 'Speaking Mate', 'Talking Run',
			'TeacherWel', 'Topsphone', 'Up Talking Club', 'Wants', 'Watjjang'
		],
		types: ['All Types', 'Phone', 'Video Skype', 'Video Zoom'],
		headers: [{
				text: 'Academy',
				align: 'left',
				value: 'academy',
			},
			{
				text: 'Class Type',
				value: 'type'
			},

			{
				text: 'Student ID',
				value: 'student'
			},

			{
				text: 'Action',
				sortable: false,
				value: 'action'
			},
		],

	}),

	methods: {

		async getAllClasses(){

await axios.get('Tutor/getAllClasses').then(res => {





this.$set(this.$data, 'Classes', res.data)



console.log(this.Classes, 'datass')

})



},

async getAllStudents(){

await axios.get('Tutor/getAllStudents').then(res => {



this.$set(this.$data, 'Students', res.data)

	console.log(this.Students, 'students')
})

},


		editClass(event, item){

			const classes = []

			this.Classes.forEach( data => {



				let schedules = data['schedule']

				if(schedules){

					schedules.forEach( schedule => {



										if(item.id === schedule['schedule']['id'] && schedule['active'] === true  && schedule['cancelled'] === false ){

											classes.push({'schedule' : schedule['schedule'], 'tutor' : data['tutor'] })
										}


					})


				}
			})

			console.log(classes, 'clazzes')
			console.log(item, 'stuent')


			this.$emit('clicked-show-edit', {target:event.target.innerText, item:classes, student: item})
		},


		getEndContract(item){

			let date = item['date']
			let months = parseInt(item['period'])
	return 	moment(date).add(months, 'month').format("YYYY/MM/DD")


		}
	},

	mounted(){


		this.getAllClasses()
			this.getAllStudents()



	}


}
</script>

<style scoped lang="css">

    .link{
      text-decoration: none;
    }

    .nav{
    	max-width: 200px;
    }

</style>
