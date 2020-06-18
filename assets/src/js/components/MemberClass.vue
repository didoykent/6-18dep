<template>
<v-app>
	<v-container>

		<v-card flat>
			<v-container class="pb-0">
				<v-row>
					<v-col cols="12" sm="4" md="2" align="center" justify="center" class=" nav">
						<v-row justify="center"><v-btn block text @click="navClick($event)">Class List</v-btn></v-row>
					</v-col>
					<v-divider vertical></v-divider>
					<v-col cols="12" sm="4" md="2" align="center" justify="center" class="nav">
							<v-row justify="center"><v-btn block text  @click="navClick($event)">Academies</v-btn></v-row>
					</v-col>
					<v-divider vertical></v-divider>
					<v-col cols="12" sm="4" md="2" align="center" justify="center" class=" nav">
							<v-row justify="center"><v-btn block text  @click="navClick($event)">Level Test List</v-btn></v-row>
					</v-col>
					<v-divider vertical></v-divider>
					<v-col cols="12" sm="4" md="2" align="center" justify="center" class=" nav">
							<v-row justify="center"><v-btn block text class="px-0"  @click="navClick($event)">Take Over List</v-btn></v-row>
					</v-col>
					<v-divider vertical></v-divider>

					<v-col cols="12" sm="4" md="2" align="center" justify="center" class=" nav">
							<v-row justify="center"><v-btn block text  @click="navClick($event)">Message Service</v-btn></v-row>
					</v-col>
					<v-divider vertical></v-divider>
					<v-col cols="12" sm="4" md="2" align="center" justify="center" class=" nav">
							<v-row justify="center"><v-btn block text  @click="navClick($event)">Coupons</v-btn></v-row>
					</v-col>
				</v-row>
			</v-container>
			<v-divider class="ma-0"></v-divider>


	<div>
		<MemberClassList  @clicked-show-edit="classListClicked" v-if="currentComponent === 'MemberClassList'"></MemberClassList>
		<MemberClassAcademies v-if="currentComponent === 'MemberClassAcademies'"></MemberClassAcademies>
		<MemberClassOutgoingCallList v-if="currentComponent === 'MemberClassOutgoingCallList'"></MemberClassOutgoingCallList>
		<MemberClassEditStudent  :studentClass = "studentClass"  :student = "student"  v-if="currentComponent === 'MemberClassEditStudent'"></MemberClassEditStudent>
	</div>





		</v-card>

	</v-container>
</v-app>
</template>


<script>
import axios from 'axios'
			import MemberClassAcademies from './MemberClassAcademies'
			import MemberClassList from './MemberClassList'
			import MemberClassOutgoingCallList from './MemberClassOutgoingCallList'
			import MemberClassEditStudent from './MemberClassEditStudent'


export default {

	components: {MemberClassAcademies, MemberClassList, MemberClassOutgoingCallList, MemberClassEditStudent},

	data: vm => ({

		currentComponent: 'MemberClassList',
		tab: null,

		Classes: [],

		studentClass: [],

		student: [],

		Tutor: [],

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
				text: 'Class ID',
				value: 'class'
			},
			{
				text: 'Student ID',
				value: 'student'
			},
			{
				text: 'End of Contract',
				value: 'end_contract'
			},
			{
				text: 'Action',
				sortable: false,
				value: 'action'
			},
			{
				text: 'Recordings',
				sortable: false,
				value: 'recording'
			},
		],

		test: '',
	}),


	mounted(){



	},

	methods: {

			navClick(selected){
				if(selected.target.innerText == 'CLASS LIST'){
						this.currentComponent = 'MemberClassList'
				}else if(selected.target.innerText == 'ACADEMIES'){
						this.currentComponent = 'MemberClassAcademies'
				}
				else if(selected.target.innerText == 'OUTGOING CALL LIST'){
						this.currentComponent = 'MemberClassOutgoingCallList'
				}
			},

			classListClicked(value){

				console.log(value, 'value')
					if(value.target == 'edit'){
							this.currentComponent = 'MemberClassEditStudent'

							this.studentClass = value.item
							this.student = value.student


							console.log(this.studentClass, 'student')
					}
			},

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
