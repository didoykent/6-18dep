<template >
<v-app>

	<v-overlay :value="verifyReferenceNumberLoading">
		<v-progress-circular indeterminate size="64"></v-progress-circular>
	</v-overlay>
	<v-row>

		<v-col class="pa-4">

			<v-row class="display-1 ml-1">
				Class Information
			</v-row>

			<v-card>
				<v-tabs vertical>


					<v-tab class="ml-0 pl-0">
						<v-checkbox  v-model = "category"   value = "leveltest" label="Level Test"></v-checkbox>
					</v-tab>


					<v-tab class="ml-4">
						<v-checkbox v-model = "category"    value = "regularclass" class="mx-2" label="Regular Class"></v-checkbox>
					</v-tab>

					<v-tab-item>
						<v-card flat>
							<v-card-text>

								<v-row>
									<v-col cols="12" sm="12" md="3" class="pb-0">
										<span class = "red--text" v-if = "getLeveltestError && getLeveltestError['academy']">{{getLeveltestError['academy']}}</span>
										<v-select :items="academies" v-model="memberLeveltest.academy" label="Academy" outlined></v-select>
									</v-col>
									<v-col cols="12" sm="12" md="3" class="pb-0">
												<span class = "red--text" v-if = "getLeveltestError && getLeveltestError['class_type']">{{getLeveltestError['class_typey']}}</span>
										<v-select :items="types" v-model="memberLeveltest.class_type" label="Type" @change="onChange($event)" outlined></v-select>
									</v-col>
									<v-col sm="6" md="3" class="pb-0">
										<v-menu ref="menu1" v-model="menu1" :close-on-content-click="false" transition="scale-transition" offset-y full-width max-width="290px" min-width="290px">
											<template v-slot:activator="{ on }">
														<v-text-field v-model="dateFormatted" label="Date" hint="MM/DD/YYYY format"
													@blur="date = parseDate(dateFormatted)" outlined v-on="on"></v-text-field>
											</template>
																									<span class = "red--text" v-if = "getLeveltestError && getLeveltestError['date']">{{getLeveltestError['date']}}</span>
											<v-date-picker   v-model="date" no-title @input="menu1 = false"></v-date-picker>
										</v-menu>
									</v-col>
									<v-col cols="12" sm="12" md="1" class="pb-0">
												<span class = "red--text" v-if = "getLeveltestError && getLeveltestError['hour']">{{getLeveltestError['hour']}}</span>
										<v-select :items="hours" v-model="memberLeveltest.hour" label="Hour" outlined></v-select>
									</v-col>

									<v-col cols="12" sm="12" md="2" class="pb-0">
												<span class = "red--text" v-if = "getLeveltestError && getLeveltestError['minute']">{{getLeveltestError['minute']}}</span>
										<v-select :items="minutes" v-model="memberLeveltest.minute" label="Minutes" outlined></v-select>
									</v-col>
								</v-row>

								<v-row align="end">
									<v-col cols="12" sm="12" md="3" class="pb-0">
												<span class = "red--text" v-if = "getLeveltestError && getLeveltestError['duration']">{{getLeveltestError['duration']}}</span>
										<v-select :items="durations" v-model="memberLeveltest.duration" label="Duration"  outlined></v-select>
									</v-col>

									<v-col cols="12" sm="12" md="3" class="pb-0" v-if = "hasSkypeId">

										<v-text-field class="pb-0"  v-model="memberLeveltest.skypeId" placeholder="Skype Id" outlined></v-text-field>
									</v-col>


									<v-spacer></v-spacer>
							<v-btn color="success"  :disabled = "!verifyRequiredValues" outlined class="mb-2 mr-3" @click="availableTutors('leveltest')">Verify</v-btn>
								</v-row>


								<v-expansion-panels v-if="Tutors.length">
									<v-expansion-panel v-for="(Tutor,i) in Tutors" :key="i">

										<v-expansion-panel-header>
											<v-checkbox v-model="memberLeveltest.selectedTutor" :value="Tutor" :label="Tutor.mega_name" />
											<template v-slot:actions v-if = "Tutor.warning">
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

								<v-row class="mt-4">

									<v-col cols="12" sm="6" md="5" class="pb-0">
												<span class = "red--text" v-if = "getLeveltestError && getLeveltestError['name']">{{getLeveltestError['name']}}</span>
										<v-text-field class="pb-0" label="English Name" v-model="memberLeveltest.name" placeholder="English Name" outlined></v-text-field>
									</v-col>

									<v-col cols="12" sm="6" md="5" class="pb-0">
												<span class = "red--text" v-if = "getLeveltestError && getLeveltestError['name']">{{getLeveltestError['name']}}</span>
										<v-text-field class="pb-0" label="Korean Name" v-model="memberLeveltest.kr_name" placeholder="Korean Name" outlined></v-text-field>
									</v-col>
									<v-col cols="12" sm="6" md="5" class="pb-0">
												<span class = "red--text" v-if = "getLeveltestError && getLeveltestError['phone_number']">{{getLeveltestError['phone_number']}}</span>
										<v-text-field class="pb-0" label="Phone Number" v-model="memberLeveltest.phone_number" placeholder="Phone Number" outlined></v-text-field>
									</v-col>
								</v-row>

								<v-row>
									<v-spacer></v-spacer>
									<div class="my-2 mr-2">
										<v-btn color="primary"  :disabled = "!verify" @click="addLevelTest">Submit</v-btn>
									</div>
								</v-row>

							</v-card-text>
						</v-card>
					</v-tab-item>
					<v-tab-item>

						<v-card flat>
							<v-card-text>
								<v-row>
									<v-col cols="12" sm="12" md="5" class="pb-0">
											<span class = "red--text" v-if = "getRegularclassError && getRegularclassError['academy']">{{getRegularclassError['academy']}}</span>
										<v-select :items="academies" v-model="memberRegularClass.academy" @change="onChangeAcademy($event)" label="Academy" outlined></v-select>
									</v-col>
									<!--	<v-col cols="12" sm="12" md="5" class="pb-0">
										<v-select :items="levels" v-model="memberRegularClass.level" label="Level" outlined></v-select>
									</v-col> -->

								</v-row>
								<v-row>
									<v-col>
										<v-row>
											<v-col cols="12" sm="12" md="5" class="pb-0">
												<span class = "red--text" v-if = "getRegularclassError && getRegularclassError['class_type']">{{getRegularclassError['class_type']}}</span>
												<v-select :items="types" label="Class Type" v-model="memberRegularClass.class_type" @change="onChange($event), checkPrice()" outlined></v-select>
											</v-col>
											<v-col cols="12" sm="12" md="5" class="pb-0">
												<span class = "red--text" v-if = "getRegularclassError && getRegularclassError['days']">{{getRegularclassError['days']}}</span>
												<v-select :items="days" v-model="memberRegularClass.days" label="Day/s a Week" outlined @change="onChangeDays($event), checkPrice()"></v-select>
											</v-col>

											<v-col  sm="12"  class="pb-0" v-if = "hasSkypeId">

												<v-text-field class="pb-0"  v-model="memberRegularClass.skypeId" placeholder="Skype Id" outlined></v-text-field>
											</v-col>
										</v-row>
										<v-col>
											<v-row sm="12" md="6">

												<v-menu ref="menu2" v-model="menu2" :close-on-content-click="false" transition="scale-transition" offset-y full-width max-width="290px" min-width="290px">
													<template v-slot:activator="{ on }">

														<v-text-field v-model="dateFormatted" label="Start Date" hint="MM/DD/YYYY format" @blur="date = parseDate(dateFormatted)" outlined v-on="on"></v-text-field>
													</template>
														<span class = "red--text" v-if = "getRegularclassError && getRegularclassError['date']">{{getRegularclassError['date']}}</span>
													<v-date-picker v-model="date" no-title @input="menu2 = false"></v-date-picker>
												</v-menu>

											</v-row>
										</v-col>
									</v-col>

									<v-col cols="12" sm="12" md="5" class="pb-0">
										<span class = "red--text" v-if = "getRegularclassError && getRegularclassError['applicable_days']">{{getRegularclassError['applicable_days']}}</span>
										<v-card>
											<v-card-text>
												<v-row class="mb-4 ml-2 subtitle-1">
													Check applicable days
												</v-row>
												<v-row align="center" justify="center">
													<v-col cols="2" class="py-0 text-center ">
														M
													</v-col>
													<v-col cols="2" class="py-0 text-center">
														T
													</v-col>
													<v-col cols="2" class="py-0 text-center">
														W
													</v-col>
													<v-col cols="2" class="py-0 text-center">
														Th
													</v-col>
													<v-col cols="2" class="py-0 text-center">
														F
													</v-col>
												</v-row>
												<v-row class="pl-3" align="center" justify="center">
													<v-col cols="2" class="py-0">
														<v-checkbox value="M" v-model="applicableDays[0]" :disabled="disableDay1" :input-value="inputValue1"></v-checkbox>
													</v-col>
													<v-col cols="2" class="py-0">
														<v-checkbox value="T" v-model="applicableDays[1]" :disabled="disableDay2" :input-value="inputValue2"></v-checkbox>
													</v-col>
													<v-col cols="2" class="py-0">
														<v-checkbox value="W" v-model="applicableDays[2]" :disabled="disableDay3" :input-value="inputValue3"></v-checkbox>
													</v-col>
													<v-col cols="2" class="py-0">
														<v-checkbox value="TH" v-model="applicableDays[3]" :disabled="disableDay4" :input-value="inputValue4"></v-checkbox>
													</v-col>
													<v-col cols="2" class="py-0">
														<v-checkbox value="F" v-model="applicableDays[4]" :disabled="disableDay5" :input-value="inputValue5"></v-checkbox>
													</v-col>
												</v-row>
											</v-card-text>
										</v-card>


									</v-col>
								</v-row>

								<v-row>
									<v-col cols="12" sm="12" md="3" class="pb-0 display-1 text-center">
										Time
									</v-col>

									<v-col cols="12" sm="12" md="2" class="pb-0">
													<span class = "red--text" v-if = "getRegularclassError && getRegularclassError['hour']">{{getRegularclassError['hour']}}</span>
										<v-select :items="hours" v-model="memberRegularClass.hour" label="Hour" outlined></v-select>
									</v-col>
									<v-col cols="12" sm="12" md="2" class="pb-0">
												<span class = "red--text" v-if = "getRegularclassError && getRegularclassError['minute']">{{getRegularclassError['minute']}}</span>
										<v-select :items="minutes" v-model="memberRegularClass.minute" label="Minutes" outlined></v-select>
									</v-col>
								</v-row>

								<v-row>
									<v-col cols="12" sm="12" md="3" class="pb-0">
												<span class = "red--text" v-if = "getRegularclassError && getRegularclassError['duration']">{{getRegularclassError['duration']}}</span>
										<v-select :items="durations" label="Duration" v-model="memberRegularClass.duration" @change="checkPrice()" outlined></v-select>
									</v-col>


									<v-col cols="12" sm="12" md="3" class="pb-0">
												<span class = "red--text" v-if = "getRegularclassError && getRegularclassError['period']">{{getRegularclassError['period']}}</span>
										<v-select :items="periods" label="Period" v-model="memberRegularClass.period" @change="checkPrice()" outlined></v-select>
									</v-col>

									<v-col cols="12" sm="12" md="5" class="pb-0">
										<v-row>
											<v-card class="pa-2 mb-2" flat>
												<span class="mr-5 headline font-weight-black">Price:</span>
											</v-card>
											<v-card class="pa-2">
												<span class="mr-5 headline font-weight-black">{{krw}}</span>
												<span class="headline font-weight-black">{{price}}</span>
											</v-card>
										</v-row>
									</v-col>
								</v-row>



								<v-row align="end">
									<v-spacer></v-spacer>
										<v-btn color="success"  :disabled = "!verifyRequiredValues" outlined class="mb-2 mr-3" @click="availableTutors('regularclass')">Verify</v-btn>
								</v-row>

								<v-expansion-panels>
									<v-expansion-panel v-for="(Tutor,i) in Tutors" :key="i">

										<v-expansion-panel-header>
											<v-checkbox v-model="memberRegularClass.selectedTutor" :value="Tutor" :label="Tutor.mega_name" />
											<template v-slot:actions v-if = "Tutor.warning">
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



								<v-sheet color="grey lighten-3" width="100%" height="100%" class="pa-3">
	    <v-switch v-model="hasLevelTest" flat :label="`HasLevelTest: ${hasLevelTest.toString()}`"></v-switch>
			<v-col cols="12" sm="12" md="4" class="pb-0"  v-if = "reference_number_error">
					<span class = "red--text">Invalid reference number.</span>
			</v-col>
			<v-col cols="12" sm="12" md="4" class="pb-0"   v-if = "reference_number_error === false">
					<span class = "green--text">Reference number found.</span>
			</v-col>
			<v-row class="mt-4" v-if="hasLevelTest">


				<v-col cols="12" sm="12" md="4" class="pb-0">


			<v-text-field class="pb-0" label="Reference number" v-model="memberRegularClass.preference_number" placeholder="Reference number" outlined></v-text-field>
				</v-col>
				<v-col cols="12" sm="12" md="4" class="pb-0">
		<v-btn color="success" x-large :disabled = "!memberRegularClass.preference_number" @click="verifyReferenceNumber">Verify</v-btn>
				</v-col>
			</v-row>

	  </v-sheet>


								<v-row class="mt-4">
									<v-col cols="12" sm="12" md="4" class="pb-0">
												<span class = "red--text" v-if = "getRegularclassError && getRegularclassError['curriculum']">{{getRegularclassError['curriculum']}}</span>
										<v-select :items="curriculums" label="Curriculum" v-model="memberRegularClass.curriculum" @change="onChangeCurriculum($event)" outlined></v-select>
									</v-col>
									<v-col cols="12" sm="12" md="4" class="pb-0">
												<span class = "red--text" v-if = "getRegularclassError && getRegularclassError['bookMaterial']">{{getRegularclassError['bookMaterial']}}</span>
										<v-select :items="books" label="Book/Material" v-model="memberRegularClass.bookMaterial" outlined></v-select>
									</v-col>
								</v-row>

								<v-row>
									<v-col cols="12" sm="6" md="3" class="pb-0">
												<span class = "red--text" v-if = "getRegularclassError && getRegularclassError['name']">{{getRegularclassError['name']}}</span>
										<v-text-field class="pb-0" label="English name" v-model="memberRegularClass.name" placeholder="English name" outlined></v-text-field>
									</v-col>

									<v-col cols="12" sm="6" md="3" class="pb-0">
												<span class = "red--text" v-if = "getRegularclassError && getRegularclassError['name']">{{getRegularclassError['name']}}</span>
										<v-text-field class="pb-0" label="Korean name" v-model="memberRegularClass.kr_name" placeholder="Korean name" outlined></v-text-field>
									</v-col>

									<v-col cols="12" sm="6" md="3" class="pb-0">
												<span class = "red--text" v-if = "getRegularclassError && getRegularclassError['phone_number']">{{getRegularclassError['phone_number']}}</span>
										<v-text-field class="pb-0" label="Phone Number" v-model="memberRegularClass.phone_number" placeholder="Phone Number" outlined></v-text-field>
									</v-col>
									<v-col cols="12" sm="6" md="3" class="pb-0">
												<span class = "red--text" v-if = "getRegularclassError && getRegularclassError['email']">{{getRegularclassError['email']}}</span>
										<v-text-field class="pb-0" label="Email" v-model="memberRegularClass.email" placeholder="Email" outlined></v-text-field>
									</v-col>
									<v-col cols="12" sm="6" md="3" class="pb-0">
												<span class = "red--text" v-if = "getRegularclassError && getRegularclassError['id']">{{getRegularclassError['id']}}</span>
										<v-text-field class="pb-0" label="ID" v-model="memberRegularClass.id" placeholder="ID" outlined></v-text-field>
									</v-col>
									<v-col cols="12" sm="6" md="3" class="pb-0">
												<span class = "red--text" v-if = "getRegularclassError && getRegularclassError['pw']">{{getRegularclassError['pw']}}</span>
										<v-text-field class="pb-0" label="Password" v-model="memberRegularClass.pw" placeholder="Password" outlined></v-text-field>
									</v-col>
								</v-row>

								<v-row>
									<v-spacer></v-spacer>
									<div class="my-2 mr-2">
										<v-btn color="primary"  :disabled = "!verify" @click="addRegularClass">UPay</v-btn>
									</div>
								</v-row>

							</v-card-text>
						</v-card>
					</v-tab-item>
				</v-tabs>
			</v-card>
		</v-col>

	</v-row>

</v-app>
</template>

<script>

import vue from 'vue'
import moment from 'moment'
import axios from 'axios'

export default {

	data: vm => ({

			rows: [],
			verifyReferenceNumberLoading: false,
			 date: new Date().toISOString().substr(0, 10),
			 hasSkypeId: false,
			 reference_number_error: '',
			 dateFormatted: vm.formatDate(new Date().toISOString().substr(0, 10)),
			 menu1: false,
			 menu2: false,
			 type2: "",
			 classType: '',
			 classPeriod: '',
			 daysInMonths: [],
				verifyRequiredValues: false,
				verify: false,
				hasLevelTest: false,





			 startPeriod: '',

			 durations: ['10 minutes' , '20 minutes'],
			periods: ['1 month', '3 months', '6 months + 1'],
			 radio1: "",
			 memberLeveltest: [],
			 memberRegularClass: [],
			 applicableDays: [],
			 Tutors: [],
			 price: "",
			 category: '',
	 krw: "",
	 disableDay1: true,
	 disableDay2: true,
	 disableDay3: true,
	 disableDay4: true,
	 disableDay5: true,
	 selectedDay: 0,
	 inputValue1: "",
	 inputValue2: "",
	 inputValue3: "",
	 inputValue4: "",
	 inputValue5: "",


			 types: ['Phone',  'Video Skype', 'Video Zoom'],
			 hours: ['5:00', '6:00', '7:00', '8:00', '9:00', '10:00', '11:00',
								 '12:00', '13:00', '14:00', '15:00', '16:00', '17:00', '18:00',
								 '19:00', '20:00', '21:00', '22:00', '23:00'],
			 minutes: ['00', '10', '20', '30', '40', '50'],

			academies: ['Alton Study', 'Anytalk', 'Bigcat', 'Daily Speaking', 'ECK Edu', 'Edunuri', 'Engforu', 'EnglishTOK', 'EverydayCN', 'Flocampus',
			 'Future', 'G Talking', 'GG Youth', 'Grace Talk', 'Himsolutek', 'Injae', 'JKOLS', 'JoongAng', 'JoongAng China', 'JTalk',
				'Kakyo Edu', 'Kingdom Edu', 'Kisan', 'LangTalk', 'LG Academy', 'Making Speaker',
				'Mangolang', 'Megatalking', 'MGEnglish', 'Mirae', 'MK Edu', 'Mot English',
			 'Narae', 'Phonetalk', 'SayOn', 'SGS', 'SKN(Kwak)', 'Speaking Mate', 'Talking Run',
			 'TeacherWel', 'Topsphone', 'Up Talking Club', 'Wants', 'Watjjang'],

			 levels: ['Low Beginner', 'Beginner', 'High Beginner', 'Low Intermediate',
			 'Intermediate', 'High Intermediate',
			 'Pre Advance', 'Advance', 'Post Advance'],

			 days: [],
			 daysNonSKN: [ '2', '3', '5'],

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



			 phone_durations: ['10 minutes', '20 minutes'],
			 video_durations: ['20 minutes', '30 minutes', '40 minutes', '50 minutes'],

			 phone_periods: ['1 month', '3 months', '6 months + 1'],
			 video_periods: ['1 month', '3 months', '6 months'],

	}),

	computed: {
      computedDateFormatted () {
        return this.formatDate(this.date)
      },

			getLeveltestError(){

				return this.$store.getters.getLeveltestError
			},

			getRegularclassError(){

				return this.$store.getters.getRegularclassError
			}
    },

		watch: {
      date (val) {
        this.dateFormatted = this.formatDate(this.date)
      },

			applicableDays: function(val){

						var days = []
						var day1 = false
						var day2 = false
						var day3 = false
						var day4 = false
						var day5 = false

						if(this.applicableDays[0] == "M"){
							day1 = true
							days.push(this.applicableDays[0])
						}
						if(this.applicableDays[1] == "T"){
							day2 = true
							days.push(this.applicableDays[1])
						}
						if(this.applicableDays[2] == "W"){
							day3 = true
							days.push(this.applicableDays[2])
						}
						if(this.applicableDays[3] == "TH"){
							day4 = true
							days.push(this.applicableDays[3])
						}
						if(this.applicableDays[4] == "F"){
							day5 = true
							days.push(this.applicableDays[4])
						}

						if(days.length >= this.memberRegularClass.days){
							console.log("reach")
								if(!day1){
									vue.set(this.$data, 'disableDay1', true)
								}
								if(!day2){
									vue.set(this.$data, 'disableDay2', true)
								}
								if(!day3){
									vue.set(this.$data, 'disableDay3', true)
								}
								if(!day4){
									vue.set(this.$data, 'disableDay4', true)
								}
								if(!day5){
									vue.set(this.$data, 'disableDay5', true)
								}
						}else if(days.length < this.memberRegularClass.days){
								vue.set(this.$data, 'inputValue1', false)
								vue.set(this.$data, 'inputValue2', false)
								vue.set(this.$data, 'inputValue3', false)
								vue.set(this.$data, 'inputValue4', false)
								vue.set(this.$data, 'inputValue5', false)
						}

			},

			'memberLeveltest.selectedTutor': {

				handler: function (after, before) {

						if(after){

							this.verify = true
						}
						else{

							this.verify = false
						}

						console.log(this.verify)

            },
            deep: true
			},

			memberLeveltest:{

				handler(oldval, newval){


					console.log(newval, 'newval')
				if(newval.class_type && this.date && newval.hour && newval.minute && newval.duration){

						this.verifyRequiredValues = true









				}
				else{

							this.verifyRequiredValues = false
				}


			},
			deep: true

			},

			memberRegularClass:{

				handler(oldval, newval){



				if(newval.class_type && this.date && newval.hour && newval.minute && newval.duration && newval.period && this.price && newval.days){

						this.verifyRequiredValues = true

						console.log(this.verifyRequiredValues)
				}

				else{

							this.verifyRequiredValues = false
				}


			},
			deep: true

			},

			'memberRegularClass.selectedTutor': {

				handler: function (after, before) {

						if(after){

							this.verify = true
						}
						else{

							this.verify = false
						}

						console.log(this.verify)

            },
            deep: true
			}




    },

		mounted(){



		},

	methods: {

		reload(type){
		localStorage.setItem('classType', type)
			location.reload()


		},

		formatDate (date) {
        if (!date) return null

        const [year, month, day] = date.split('-')
        return `${month}/${day}/${year}`
      },

      parseDate (date) {
        if (!date) return null

        const [month, day, year] = date.split('/')
        return `${year}-${month.padStart(2, '0')}-${day.padStart(2, '0')}`
      },

			onChange(event) {
						 console.log(event)
						 this.hasSkypeId = false
						 if(event == "Phone"){

							 vue.set(this.$data, 'durations', this.$data.phone_durations)
							 vue.set(this.$data, 'periods', this.$data.phone_periods)

						 }else if(event == "Video Skype" || event == "Video Zoom" ){

								vue.set(this.$data, 'durations',this.$data.video_durations)
								vue.set(this.$data, 'periods', this.$data.video_periods)
						 }

						 if(event == "Video Skype" ){

							 this.hasSkypeId = true
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

			onChangeAcademy(event) {
				/**	if (event == 'SKN(Kwak)') {
						vue.set(this.$data, 'days', this.$data.daysSKN)
					} else {} */

						vue.set(this.$data, 'days', this.$data.daysNonSKN)

				},

				onChangeDays(){

						this.applicableDays = []

						vue.set(this.$data, 'disableDay1', false)
						vue.set(this.$data, 'disableDay2', false)
						vue.set(this.$data, 'disableDay3', false)
						vue.set(this.$data, 'disableDay4', false)
						vue.set(this.$data, 'disableDay5', false)

					//handle errors/bugs for changing the days after selecting in the applicable days
					if(this.memberRegularClass.days > this.selectedDay){
						vue.set(this.$data, 'disableDay1', false)
						vue.set(this.$data, 'disableDay2', false)
						vue.set(this.$data, 'disableDay3', false)
						vue.set(this.$data, 'disableDay4', false)
						vue.set(this.$data, 'disableDay5', false)
					}

					if(this.memberRegularClass.days < this.selectedDay){
						vue.set(this.$data, 'applicableDays[]', false)
						vue.set(this.$data, 'applicableDays[1]', false)
						vue.set(this.$data, 'applicableDays[2]', false)
						vue.set(this.$data, 'applicableDays[3]', false)
						vue.set(this.$data, 'applicableDays[4]', false)
					}

					this.selectedDay = this.memberRegularClass.days

				},

				 getTutors(){

					 axios.get('Tutor/showAll').then(res => {

this.$set(this.$data, 'Tutors', res.data.tutors)
						 console.log(this.Tutors)
					 }).catch(err => {

						 console.log(err)

					 })
				 },


				 addLevelTest(){



					 var mom = moment({hour: this.memberLeveltest.hour, minute:this.memberLeveltest.minute}).format('HH:mm:ss')

					 let date  = this.date + ' '

					  let add = moment(mom, 'HH:mm:ss').add(parseInt(this.memberLeveltest.duration.replace('minutes', '')), 'minutes').format('HH:mm:ss')
					 let start_date =  date + mom

					 let end_date = date + add

					 console.log(start_date)
					 console.log(end_date)

					 this.memberLeveltest.class_start = start_date
					 this.memberLeveltest.class_end = end_date

					 this.memberLeveltest.date = this.date
					 this.memberLeveltest.selectedTutor = JSON.stringify( this.memberLeveltest.selectedTutor)



					 let weekdays = []



			if(moment(date).format('dddd') === 'Monday'){

			 weekdays.push('M')
			}
			if(moment(date).format('dddd') === 'Tuesday'){

			 weekdays.push('T')
			}

			if(moment(date).format('dddd') === 'Wednesday'){

			 weekdays.push('W')
			}

			if(moment(date).format('dddd') === 'Thursday'){

			 weekdays.push('TH')
			}

			if(moment(date).format('dddd') === 'Friday'){

			 weekdays.push('F')
			}

					 		 this.memberLeveltest.applicable_days = 	 weekdays



				this.$store.dispatch('addLevelTest', {Member: this.memberLeveltest})






					setTimeout( () => {





								if(this.getLeveltestError){

									if(!Object.keys(this.getLeveltestError).length ){






									this.verify = false

										this.price = ''





										this.Tutors = []



	vue.set(this.$data, 'memberLeveltest', [])




									}

								}




					}, 100)

					setTimeout( () =>{



					if(this.memberLeveltest.length <=0){

						vue.set(this.$data, 'verifyRequiredValues', false)

					}

			}, 200)

				 },

				 addRegularClass(){

					 this.memberRegularClass.price = this.price

					 var mom = moment({hour: this.memberRegularClass.hour, minute:this.memberRegularClass.minute}).format('HH:mm:ss')
					let date  = this.date + ' '
					 let add = moment(mom, 'HH:mm:ss').add(parseInt(this.memberRegularClass.duration.replace('minutes', '')), 'minutes').format('HH:mm:ss')
					let start_date =  date + mom

					let end_date = date + add

					this.classPeriod = ''
					this.startPeriod = ''



					if(this.memberRegularClass.period === '1 month'){

						this.classPeriod = 1


					}

					if(this.memberRegularClass.period === '3 months'){

										this.classPeriod = 3
					}

					if(this.memberRegularClass.period === '6 months'){

						this.classPeriod = 6

					}

					if(this.memberRegularClass.period === '6 months + 1'){

										this.classPeriod = 7
					}









					 this.memberRegularClass.date = this.date


					 this.memberRegularClass.applicable_days = 	this.applicableDays.filter((obj) => obj )

					 this.memberRegularClass.selectedTutor = JSON.stringify( this.memberRegularClass.selectedTutor)



					 let weekdays = []

					 for(var i =0; i<this.memberRegularClass.applicable_days.length; i++){

						 if(this.memberRegularClass.applicable_days[i] === 'M'){

							 weekdays.push(1)
						 }

						 if(this.memberRegularClass.applicable_days[i] === 'T'){

							weekdays.push(2)
						}

						if(this.memberRegularClass.applicable_days[i] === 'W'){

						 weekdays.push(3)
					 }

					 if(this.memberRegularClass.applicable_days[i] === 'TH'){

						weekdays.push(4)
					 }

					if(this.memberRegularClass.applicable_days[i] === 'F'){

					 weekdays.push(5)
				  }

					 }

							let endPeriod = moment(date).add(this.classPeriod , 'month').format('YYYY-MM-DD')

							let num = 1;

							let class_start = []
							let class_end = []
								if(weekdays.indexOf(moment(date).weekday()) != -1){


									class_start.push(start_date)
								   class_end.push(end_date)
								}


							while(this.startPeriod <= endPeriod){



								this.startPeriod = moment(date).add(num++, 'd').format('YYYY-MM-DD')

								if(weekdays.indexOf(moment(this.startPeriod).weekday()) != -1){

								class_start.push(	this.startPeriod + ' ' + mom)
								class_end.push(this.startPeriod + ' ' + add)
							}
}

this.memberRegularClass.class_start = class_start
this.memberRegularClass.class_end = class_end

console.log(class_start, 'starts')

	this.$store.dispatch('addRegularClass', {Member: this.memberRegularClass})

	setTimeout( () => {



				if(this.getRegularclassError){

				if(!Object.keys(this.getRegularclassError).length ){

					vue.set(this.$data, 'disableDay1', true)
					vue.set(this.$data, 'disableDay2', true)
					vue.set(this.$data, 'disableDay3', true)
					vue.set(this.$data, 'disableDay4', true)
					vue.set(this.$data, 'disableDay5', true)
					this.verify = false
					this.applicableDays = []

					this.price = ''
					this.memberRegularClass = []
					this.Tutors = []

}

}

}, 100)



				 },

				 availableTutors(type){




					 if(type === 'leveltest'){



						 this.classType = this.memberLeveltest


						 					 let filter = ''
						 					 					 var mom = moment({hour: this.classType.hour, minute:this.classType.minute}).format('HH:mm:ss')
						 					 					 let date  = this.date + ' '

						 					 					  let add = moment(mom, 'HH:mm:ss').add(parseInt(this.classType.duration.replace('minutes', '')), 'minutes').format('HH:mm:ss')
						 					 					 let start_date =  date + mom

						 					 					 let end_date = date + add



let weekdays = []

if(moment(date).format('dddd') === 'Monday'){

	weekdays.push('M')
}
if(moment(date).format('dddd') === 'Tuesday'){

	weekdays.push('T')
}

if(moment(date).format('dddd') === 'Wednesday'){

	weekdays.push('W')
}

if(moment(date).format('dddd') === 'Thursday'){

	weekdays.push('TH')
}

if(moment(date).format('dddd') === 'Friday'){

	weekdays.push('F')
}








																 let form = new FormData()



																	form.append('start_class', start_date)
																	form.append('end_class', end_date)
																	form.append('weekdays', weekdays)





																	axios.post('Tutor/getAvailableTutors', form ).then(res => {

																		this.$set(this.$data,  'Tutors', res.data)


console.log(res.data, 'res')

																//	this.$set(this.$data, 'Tutors', res.data)
																	 //console.log(this.Tutors, 'tutor')




																	}).catch(err => {

																		console.log(err)
																	})





						 									 }


															 if(type === 'regularclass'){

									  	 				 this.classType = this.memberRegularClass

									  					 var mom = moment({hour: this.memberRegularClass.hour, minute:this.memberRegularClass.minute}).format('HH:mm:ss')
									  					let date  = this.date + ' '
									  					 let add = moment(mom, 'HH:mm:ss').add(parseInt(this.memberRegularClass.duration.replace('minutes', '')), 'minutes').format('HH:mm:ss')
									  					let start_date =  date + mom

									  					let end_date = date + add

													this.classPeriod = ''
													this.startPeriod = ''
													this.endPeriod = ''
									  					if(this.memberRegularClass.period === '1 month'){

									  						this.classPeriod = 1


									  					}

									  					if(this.memberRegularClass.period === '3 months'){

									  										this.classPeriod = 3
									  					}

									  					if(this.memberRegularClass.period === '6 months'){

									  						this.classPeriod = 6

									  					}

									  					if(this.memberRegularClass.period === '6 months + 1'){

									  										this.classPeriod = 7
									  					}












									  					 this.memberRegularClass.applicable_days = this.applicableDays.filter((obj) => obj )





									  					 let weekdays = []

									  					 for(var i =0; i<this.memberRegularClass.applicable_days.length; i++){

									  						 if(this.memberRegularClass.applicable_days[i] === 'M'){

									  							 weekdays.push(1)
									  						 }

									  						 if(this.memberRegularClass.applicable_days[i] === 'T'){

									  							weekdays.push(2)
									  						}

									  						if(this.memberRegularClass.applicable_days[i] === 'W'){

									  						 weekdays.push(3)
									  					 }

									  					 if(this.memberRegularClass.applicable_days[i] === 'TH'){

									  						weekdays.push(4)
									  					 }

									  					if(this.memberRegularClass.applicable_days[i] === 'F'){

									  					 weekdays.push(5)
									  					}

									  					 }

									  							let endPeriod = moment(date).add(this.classPeriod , 'month').format('YYYY-MM-DD')

									  							let num = 1;

									  							let class_start = []
									  							let class_end = []
									  								if(weekdays.indexOf(moment(date).weekday()) != -1){


									  									class_start.push(start_date)
									  									 class_end.push(end_date)
									  								}

																			let startPeriod = moment(date).format('YYYY-MM-DD')
									  							while(startPeriod <= endPeriod){



									  							startPeriod = moment(date).add(num++, 'd').format('YYYY-MM-DD')

									  								if(weekdays.indexOf(moment(startPeriod).weekday()) != -1){

									  								class_start.push(	startPeriod + ' ' + mom)
									  								class_end.push(startPeriod + ' ' + add)
									  							}
									   }




										 																 let form = new FormData()

										 																	form.append('start_class', class_start)
										 																	form.append('end_class', class_end)
																											form.append('class_type', type)
																											form.append('weekdays', this.memberRegularClass.applicable_days)

										 axios.post('Tutor/getAvailableTutors', form ).then(res => {

											 this.$set(this.$data,  'Tutors', res.data)







											console.log(res.data, 'result')











											}).catch(err => {

												console.log(err)
											})


									  					 }







				 },

				 checkPrice() {

					 if (this.memberRegularClass.class_type === "Phone" && this.memberRegularClass.days === "5" && this.memberRegularClass.duration === "10 minutes" && this.memberRegularClass.period === "1 month") {
						 this.krw = "KRW"
						 this.price = "100,000"
					 }
					 if (this.memberRegularClass.class_type === "Phone" && this.memberRegularClass.days === "5" && this.memberRegularClass.duration === "10 minutes" && this.memberRegularClass.period === "3 months") {
						 this.krw = "KRW"
						 this.price = "290,000"
					 }
					 if (this.memberRegularClass.class_type === "Phone" && this.memberRegularClass.days === "5" && this.memberRegularClass.duration === "10 minutes" && this.memberRegularClass.period === "6 months + 1") {
						 this.krw = "KRW"
						 this.price = "600,000"
					 }
					 if (this.memberRegularClass.class_type === "Phone" && this.memberRegularClass.days === "5" && this.memberRegularClass.duration === "20 minutes" && this.memberRegularClass.period === "1 month") {
						 this.krw = "KRW"
						 this.price = "190,000"
					 }
					 if (this.memberRegularClass.class_type === "Phone" && this.memberRegularClass.days === "5" && this.memberRegularClass.duration === "20 minutes" && this.memberRegularClass.period === "3 months") {
						 this.krw = "KRW"
						 this.price = "560,000"
					 }
					 if (this.memberRegularClass.class_type === "Phone" && this.memberRegularClass.days === "3" && this.memberRegularClass.duration === "10 minutes" && this.memberRegularClass.period === "6 months + 1") {
						 this.krw = "KRW"
						 this.price = "70,000"
					 }
					 if (this.memberRegularClass.class_type === "Phone" && this.memberRegularClass.days === "3" && this.memberRegularClass.duration === "10 minutes" && this.memberRegularClass.period === "3 months") {
						 this.krw = "KRW"
						 this.price = "200,000"
					 }
					 if (this.memberRegularClass.class_type === "Phone" && this.memberRegularClass.days === "3" && this.memberRegularClass.duration === "10 minutes" && this.memberRegularClass.period === "6 months + 1") {
						 this.krw = "KRW"
						 this.price = "420,000"
					 }
					 if (this.memberRegularClass.class_type === "Phone" && this.memberRegularClass.days === "3" && this.memberRegularClass.duration === "20 minutes" && this.memberRegularClass.period === "1 month") {
						 this.krw = "KRW"
						 this.price = "130,000"
					 }
					 if (this.memberRegularClass.class_type === "Phone" && this.memberRegularClass.days === "3" && this.memberRegularClass.duration === "20 minutes" && this.memberRegularClass.period === "3 months") {
						 this.krw = "KRW"
						 this.price = "380,000"
					 }
					 if (this.memberRegularClass.class_type === "Phone" && this.memberRegularClass.days === "3" && this.memberRegularClass.duration === "20 minutes" && this.memberRegularClass.period === "6 months + 1") {
						 this.krw = "KRW"
						 this.price = "780,000"
					 }
					 if (this.memberRegularClass.class_type === "Phone" && this.memberRegularClass.days === "2" && this.memberRegularClass.duration === "10 minutes" && this.memberRegularClass.period === "1 month") {
						 this.krw = "KRW"
						 this.price = "45,000 "
					 }
					 if (this.memberRegularClass.class_type === "Phone" && this.memberRegularClass.days === "2" && this.memberRegularClass.duration === "10 minutes" && this.memberRegularClass.period === "3 months") {
						 this.krw = "KRW"
						 this.price = "125,000"
					 }
					 if (this.memberRegularClass.class_type === "Phone" && this.memberRegularClass.days === "2" && this.memberRegularClass.duration === "10 minutes" && this.memberRegularClass.period === "6 months + 1") {
						 this.krw = "KRW"
						 this.price = "270,000"
					 }
					 if (this.memberRegularClass.class_type === "Phone" && this.memberRegularClass.days === "2" && this.memberRegularClass.duration === "20 minutes" && this.memberRegularClass.period === "1 month") {
						 this.krw = "KRW"
						 this.price = "80,000"
					 }
					 if (this.memberRegularClass.class_type === "Phone" && this.memberRegularClass.days === "2" && this.memberRegularClass.duration === "20 minutes" && this.memberRegularClass.period === "3 months") {
						 this.krw = "KRW"
						 this.price = "230,000"
					 }
					 if (this.memberRegularClass.class_type === "Phone" && this.memberRegularClass.days === "2" && this.memberRegularClass.duration === "20 minutes" && this.memberRegularClass.period === "6 months + 1") {
						 this.krw = "KRW"
						 this.price = "480,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "2" && this.memberRegularClass.duration === "20 minutes" && this.memberRegularClass.period ===
						 "1 month") {
						 this.krw = "KRW"
						 this.price = "88,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "2" && this.memberRegularClass.duration === "20 minutes" && this.memberRegularClass.period ===
						 "3 months") {
						 this.krw = "KRW"
						 this.price = "250,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "2" && this.memberRegularClass.duration === "20 minutes" && this.memberRegularClass.period ===
						 "6 months") {
						 this.krw = "KRW"
						 this.price = "475,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "3" && this.memberRegularClass.duration === "20 minutes" && this.memberRegularClass.period ===
						 "1 month") {
						 this.krw = "KRW"
						 this.price = "118,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "3" && this.memberRegularClass.duration === "20 minutes" && this.memberRegularClass.period ===
						 "3 months") {
						 this.krw = "KRW"
						 this.price = "337,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "3" && this.memberRegularClass.duration === "20 minutes" && this.memberRegularClass.period ===
						 "6 months") {
						 this.krw = "KRW"
						 this.price = "637,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "5" && this.memberRegularClass.duration === "20 minutes" && this.memberRegularClass.period ===
						 "1 month") {
						 this.krw = "KRW"
						 this.price = "148,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "5" && this.memberRegularClass.duration === "20 minutes" && this.memberRegularClass.period ===
						 "3 months") {
						 this.krw = "KRW"
						 this.price = "442,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "5" && this.memberRegularClass.duration === "20 minutes" && this.memberRegularClass.period ===
						 "6 months") {
						 this.krw = "KRW"
						 this.price = "779,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "2" && this.memberRegularClass.duration === "30 minutes" && this.memberRegularClass.period ===
						 "1 month") {
						 this.krw = "KRW"
						 this.price = "120,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "2" && this.memberRegularClass.duration === "30 minutes" && this.memberRegularClass.period ===
						 "3 months") {
						 this.krw = "KRW"
						 this.price = "324,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "2" && this.memberRegularClass.duration === "30 minutes" && this.memberRegularClass.period ===
						 "6 months") {
						 this.krw = "KRW"
						 this.price = "628,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "3" && this.memberRegularClass.duration === "30 minutes" && this.memberRegularClass.period ===
						 "1 month") {
						 this.krw = "KRW"
						 this.price = "162,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "3" && this.memberRegularClass.duration === "30 minutes" && this.memberRegularClass.period ===
						 "3 months") {
						 this.krw = "KRW"
						 this.price = "462,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "3" && this.memberRegularClass.duration === "30 minutes" && this.memberRegularClass.period ===
						 "6 months") {
						 this.krw = "KRW"
						 this.price = "875,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "5" && this.memberRegularClass.duration === "30 minutes" && this.memberRegularClass.period ===
						 "1 month") {
						 this.krw = "KRW"
						 this.price = "210,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "5" && this.memberRegularClass.duration === "30 minutes" && this.memberRegularClass.period ===
						 "3 months") {
						 this.krw = "KRW"
						 this.price = "599,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "5" && this.memberRegularClass.duration === "30 minutes" && this.memberRegularClass.period ===
						 "6 months") {
						 this.krw = "KRW"
						 this.price = "1,134,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "2" && this.memberRegularClass.duration === "40 minutes" && this.memberRegularClass.period ===
						 "1 month") {
						 this.krw = "KRW"
						 this.price = "114,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "2" && this.memberRegularClass.duration === "40 minutes" && this.memberRegularClass.period ===
						 "3 months") {
						 this.krw = "KRW"
						 this.price = "410,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "2" && this.memberRegularClass.duration === "40 minutes" && this.memberRegularClass.period ===
						 "6 months") {
						 this.krw = "KRW"
						 this.price = "778,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "3" && this.memberRegularClass.duration === "40 minutes" && this.memberRegularClass.period ===
						 "1 month") {
						 this.krw = "KRW"
						 this.price = "192,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "3" && this.memberRegularClass.duration === "40 minutes" && this.memberRegularClass.period ===
						 "3 months") {
						 this.krw = "KRW"
						 this.price = "547,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "3" && this.memberRegularClass.duration === "40 minutes" && this.memberRegularClass.period ===
						 "6 months") {
						 this.krw = "KRW"
						 this.price = "1.037,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "5" && this.memberRegularClass.duration === "40 minutes" && this.memberRegularClass.period ===
						 "1 month") {
						 this.krw = "KRW"
						 this.price = "240,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "5" && this.memberRegularClass.duration === "40 minutes" && this.memberRegularClass.period ===
						 "3 months") {
						 this.krw = "KRW"
						 this.price = "684,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "5" && this.memberRegularClass.duration === "40 minutes" && this.memberRegularClass.period ===
						 "6 months") {
						 this.krw = "KRW"
						 this.price = "1.296,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "2" && this.memberRegularClass.duration === "50 minutes" && this.memberRegularClass.period ===
						 "1 month") {
						 this.krw = "KRW"
						 this.price = "162,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "2" && this.memberRegularClass.duration === "50 minutes" && this.memberRegularClass.period ===
						 "3 months") {
						 this.krw = "KRW"
						 this.price = "461,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "2" && this.memberRegularClass.duration === "50 minutes" && this.memberRegularClass.period ===
						 "6 months") {
						 this.krw = "KRW"
						 this.price = "874,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "3" && this.memberRegularClass.duration === "50 minutes" && this.memberRegularClass.period ===
						 "1 month") {
						 this.krw = "KRW"
						 this.price = "218,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "3" && this.memberRegularClass.duration === "50 minutes" && this.memberRegularClass.period ===
						 "3 months") {
						 this.krw = "KRW"
						 this.price = "621,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "3" && this.memberRegularClass.duration === "50 minutes" && this.memberRegularClass.period ===
						 "6 months") {
						 this.krw = "KRW"
						 this.price = "1,177,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "5" && this.memberRegularClass.duration === "50 minutes" && this.memberRegularClass.period ===
						 "1 month") {
						 this.krw = "KRW"
						 this.price = "273,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "5" && this.memberRegularClass.duration === "50 minutes" && this.memberRegularClass.period ===
						 "3 months") {
						 this.krw = "KRW"
						 this.price = "777,000"
					 }
					 if ((this.memberRegularClass.class_type === "Video Skype" || this.memberRegularClass.class_type === "Video Zoom") && this.memberRegularClass.days === "5" && this.memberRegularClass.duration === "50 minutes" && this.memberRegularClass.period ===
						 "6 months") {
						 this.krw = "KRW"
						 this.price = "1,470,000"
					 }
					 if (this.memberRegularClass.class_type !== "" && (this.memberRegularClass.days === "4" || this.memberRegularClass.days === "1") && this.memberRegularClass.duration !== "" && this.memberRegularClass.period !== "") {
						 this.price = ""
						 this.krw = ""
					 }
				 },


				 getDate(){

			let weekdays = []

let date = this.date

if(moment(date).format('dddd') === 'Monday'){

	weekdays.push('M')
}
if(moment(date).format('dddd') === 'Tuesday'){

	weekdays.push('T')
}

if(moment(date).format('dddd') === 'Wednesday'){

	weekdays.push('W')
}

if(moment(date).format('dddd') === 'Thursday'){

	weekdays.push('TH')
}

if(moment(date).format('dddd') === 'Friday'){

	weekdays.push('F')
}



},

verifyReferenceNumber(){

	if(this.memberRegularClass.preference_number){

			this.verifyReferenceNumberLoading = true

		const form = new FormData()

			form.append('preference_number', this.memberRegularClass.preference_number)

			axios.post('Evaluation/getReferenceNumber', form).then(res => {

				if(res.data){


					const evaluation = JSON.parse(res.data)

					if(evaluation){

						this.memberRegularClass.curriculum = evaluation.Curriculum
						 this.onChangeCurriculum(this.memberRegularClass.curriculum)
						this.memberRegularClass.bookMaterial =  evaluation.Material
						this.memberRegularClass.level = evaluation.Level
					}
				this.reference_number_error = false

				this.verifyReferenceNumberLoading = false
				console.log(evaluation)
				console.log(this.memberRegularClass, 'tes')
				}
				else{

					this.reference_number_error = true
				this.verifyReferenceNumberLoading = false
				}


			})
	}
}

	},


}
</script>

<style lang="css">

</style>
