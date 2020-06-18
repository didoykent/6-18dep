<template>
	<v-container>

		<v-overlay :value="availableTutorLoading">
			<v-progress-circular indeterminate size="64"></v-progress-circular>
		</v-overlay>
		<!--  <v-row class="mt-3 ml-2">
		<v-divider vertical></v-divider>
		<v-col cols="12" sm="3" md="2"  justify="center" class=" nav px-0">
		<v-btn block text class="mr-3">Student Information</v-btn>
	</v-col>
	<v-divider vertical></v-divider>
	<v-col cols="12" sm="3" md="2" align="center" justify="center" class="nav px-0">
	<v-btn block class="px-0"  text>History</v-btn>
</v-col>
<v-divider vertical></v-divider>
<v-col cols="12" sm="3" md="2" align="center" justify="center" class="nav px-0">
<v-btn block text>Writing Correction</v-btn>
</v-col>
<v-divider vertical></v-divider>
<v-col cols="12" sm="3" md="2" align="center" justify="center" class="nav px-0">
<v-btn block text>Q & A</v-btn>
</v-col>
<v-divider vertical></v-divider>
</v-row> -->


<v-row>
	<v-tabs>
		<v-tab>Student Information</v-tab>
		<v-tab>History</v-tab>
		<v-tab>Writing Correction</v-tab>
		<v-tab>Q & A</v-tab>

		<v-tab-item class="pa-2">

			<div class="float-right">
				<v-row class="ma-2 mb-4">
					<button class="float-right ml-2 v-btn v-btn--depressed theme--light" style="background-color:#E91E63" icon>
						<v-icon color="#F8BBD0" x-large>insert_chart</v-icon>
					</button>
				</v-row>
				<v-row class="ma-2 mb-4">
					<button class="float-right ml-2 v-btn v-btn--depressed theme--light" style="background-color:#E91E63" icon>
						<v-icon color="#F8BBD0" x-large>add</v-icon>
					</button>
				</v-row>
				<v-row class="ma-2 mb-4">
					<button class="float-right ml-2 v-btn v-btn--depressed theme--light" style="background-color:#E91E63" icon>
						<v-icon color="#F8BBD0" x-large>textsms</v-icon>
					</button>
				</v-row>
			</div>

			<v-hover v-slot:default="{ hover }">
				<v-card class="pt-2" max-width="500">
					<div class="mr-2" v-if="isEditButton">
						<button v-if="hover" @click="editStudent()" class="float-right ml-2 v-btn v-btn--depressed theme--light" style="background-color:#E91E63" icon>
							<v-icon color="#F8BBD0" large>edit</v-icon>
						</button>
					</div>
					<v-row class="pl-4 pt-2 pb-3">
						<v-col cols="7" class="headline text--black">
							Account Information
						</v-col>
						<v-col cols="2">
							<v-btn v-if="isEdit" color="success" small @click = "updateStudent(student)">Update</v-btn>
						</v-col>
						<v-col cols="2">
							<v-btn v-if="isEdit" @click="cancel()" small>Cancel</v-btn>
						</v-col>
					</v-row>


					<v-card flat max-width="500">


						<v-simple-table width="100%">
							<template v-slot:default>
								<tbody>
									<tr>
										<td class="account_table font-weight-bold">Student ID</td>
										<td class="account_table">{{student['id']}}</td>
									</tr>
									<tr>
										<td class="account_table font-weight-bold">Name</td>
										<td class="account_table">{{student['name']}}</td>
									</tr>
									<tr>
										<td class="account_table font-weight-bold">Phone Number</td>
										<td class="account_table" v-if="isSetPhone">{{student['phone_number']}}</td>
										<td class="account_table" v-if="!isSetPhone">
											<v-text-field class="mt-2" v-model = "student.phone_number" placeholder="Phone Number" regular></v-text-field>
										</td>
									</tr>
									<tr>
										<td class="account_table font-weight-bold">Email Adress</td>
										<td class="account_table" v-if="isSetEmail">{{student['email']}}</td>
										<td class="account_table" v-if="!isSetEmail">
											<v-text-field class="mt-2" v-model = "student.email" placeholder="Email" regular></v-text-field>
										</td>
									</tr>
									<tr>
										<td class="account_table font-weight-bold">Password</td>
										<td class="account_table">
											<v-btn color="info">Reset</v-btn>
										</td>
									</tr>
									<tr>
										<td class="account_table font-weight-bold">Recordings</td>
										<td class="account_table" v-if="isSetRecordings"></td>
										<td class="account_table" v-if="!isSetRecordings">
											<v-radio-group row v-model = "student.recordings">
												<v-radio label="Yes" value = 1 ></v-radio>
												<v-radio label="No" value = 0 ></v-radio>
											</v-radio-group>
										</td>
									</tr>
									<tr>
										<td class="account_table font-weight-bold">Take Over</td>
										<td class="account_table" v-if="isSetTakeOver"></td>
										<td class="account_table" v-if="!isSetTakeOver">
											<v-radio-group row v-model = "student.takeover">
												<v-radio label="Yes" value = 1 ></v-radio>
												<v-radio label="No" value = 0 ></v-radio>
											</v-radio-group>
										</td>
									</tr>
								</tbody>
							</template>
						</v-simple-table>
					</v-card>

				</v-card>
			</v-hover>

			<v-card>
				<v-row class="headline text--black pl-4 pt-2 pb-3 mt-2">
					Class Information
				</v-row>

				<v-row>
					<v-container>
						<v-simple-table width="100%">
							<template v-slot:default>
								<thead>
									<tr>
										<th>#</th>
										<th>Class ID</th>
										<th>Class Type</th>
										<th>Contract</th>
										<th>Days</th>
										<th>Schedule</th>
										<th>Duration</th>
										<th>Material</th>
										<th>Teacher</th>
										<th>Actions</th>
									</tr>
								</thead>
								<tbody>
									<tr v-for="studentclass in studentClass">
										<td>1</td>
										<td>{{studentclass['schedule']['classid']}}</td>
										<td>{{studentclass['schedule']['class_type']}}</td>
										<td>{{getContract(studentclass)}}</td>
										<td>{{studentclass['schedule']['applicable_days']}}</td>
										<td>


											<span @click="availableTeacher(studentclass)"><u>{{getSchedule(studentclass)}}</u></span>


											<v-dialog v-model="changeTimeDialog1" persistent max-width="550" max-height="500">



												<v-card class="pa-4">
													<v-card-title class="headline" style="background-color:#E0E0E0;">Change Time</v-card-title>
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
																				<td>{{studentclass['schedule']['classid']}}</td>
																				<td>{{studentclass['schedule']['applicable_days']}}</td>
																				<td>{{getSchedule(studentclass)}}</td>
																				<td>{{studentclass['schedule']['duration']}} minutes</td>
																			</tr>
																		</tbody>
																	</template>
																</v-simple-table>
															</v-container>
														</v-row>
													</v-card>

													<v-row justify="center">
														<v-alert color="success" dense elevation="5" class="white--text">
															<center> Your teacher can accomodate your class at another time.</center>
															<center>Please choose your desired schedule.</center>
														</v-alert>
													</v-row>

													<v-row>
														<v-col cols="12" sm="12" class="pb-0">
															<v-menu v-model="menu" :close-on-content-click="false" transition="scale-transition" offset-y full-width max-width="290px" min-width="290px">
																<template v-slot:activator="{ on }">
																	<v-text-field outlined v-model="computedDateFormatted" label="Start Date" placeholder="MM/DD/YYYY format" v-on="on"></v-text-field>
																</template>
																<v-date-picker @change="setDate()" :min="getMin(studentclass)" :max="getMax(studentclass)" :allowed-dates="allowedDates" v-model="date" no-title @input="menu = false"></v-date-picker>
															</v-menu>
														</v-col>
													</v-row>
													<v-row>
														<v-col cols="12" sm="12" class="pt-0">
															<v-select v-model="hour" @change="setMinutes()" :items="time" label="Hour" outlined></v-select>
														</v-col>


													</v-row>

													<v-row>
														<v-col cols="12" sm="12" class="pt-0">
															<v-select @change="checkHourMin()" v-model="minute" :disabled="minutes.length <= 0" :items="minutes" label="Minute" outlined></v-select>
														</v-col>


													</v-row>

													<v-row>
														<v-col cols="12" sm="12" class="pt-0">
															<v-textarea outlined label="Reason"></v-textarea>
														</v-col>
													</v-row>

													<v-row>
														<v-spacer></v-spacer>
														<v-btn class="mr-2" @click="changeTimeDialog1 = false" small>Cancel</v-btn>
														<v-btn class="mr-3" color="primary" @click="changeTime(studentclass)" small>Submit</v-btn>
													</v-row>

												</v-card>
											</v-dialog>



											<v-dialog v-model="changeTimeDialog2" persistent max-width="900" max-height="500">
												<template v-slot:activator="{ on }" v-if="!changeTimeTeacherAvailable">
													<span v-on="on"><u>5:00</u></span>
												</template>
												<v-card class="pa-4">
													<v-card-title class="headline" style="background-color:#E0E0E0;">Change Time</v-card-title>
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
																						<td>112233</td>
																						<td>MWF</td>
																						<td>5:00</td>
																						<td>30 minutes</td>
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
																<center> Your teacher cannot accomodate your class at another time.</center>
																<center>But we can find another teacher for your desired schedule.</center>
															</v-alert>
														</v-col>
													</v-row>

													<v-row>
														<v-col cols="4" class="pt-0">
															<v-menu v-model="menu" :close-on-content-click="false" transition="scale-transition" offset-y full-width max-width="290px" min-width="290px">
																<template v-slot:activator="{ on }">
																	<v-text-field outlined v-model="computedDateFormatted" label="Start Date" placeholder="MM/DD/YYYY format" v-on="on"></v-text-field>
																</template>
																<v-date-picker v-model="date" no-title @input="menu = false"></v-date-picker>
															</v-menu>
														</v-col>
														<v-col cols="4" class="pt-0" align="center">
															<v-select :items="time" label="Desired New Schedule" outlined></v-select>
														</v-col>
														<v-col cols="4">
															<v-btn color="success" @click="changeTimeVerifyTeacher = true">Check Available Teacher</v-btn>
														</v-col>
													</v-row>

													<v-row class="mb-4 mx-1" v-if="changeTimeVerifyTeacher">
														<v-expansion-panels>
															<v-expansion-panel v-for="(Tutor,i) in 4" :key="i">
																<v-expansion-panel-header>
																	Tutor {{i}}
																</v-expansion-panel-header>
																<v-expansion-panel-content>
																	Information
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
														<v-btn class="mr-2" @click="changeTimeDialog2 = false" small>Cancel</v-btn>
														<v-btn class="mr-3" color="primary" @click="changeTimeDialog2 = false" small>Apply Changes</v-btn>
													</v-row>


												</v-card>
											</v-dialog>

										</td>

										<td>{{studentclass['schedule']['duration']}} minutes </td>

										<td>{{studentclass['schedule']['bookMaterial']}}</td>

										<td>
											<v-dialog v-model="changeTeacherDialog1" persistent max-width="900" max-height="500">
												<template v-slot:activator="{ on }" v-if="changeTeacherSameTime">
													<span @click="changeTeacher(studentclass)"><u>{{studentclass['tutor']['mega_name']}}</u></span>
												</template>
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
																						<td>{{studentclass['schedule']['classid']}}</td>
																						<td>{{studentclass['schedule']['applicable_days']}}</td>
																						<td>{{getSchedule(studentclass)}}</td>
																						<td>{{studentclass['schedule']['minute']}} minutes</td>
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
														<v-btn class="mr-2" @click="changeTeacherDialog1 = false" small>Cancel</v-btn>
														<v-btn class="mr-3" color="primary" @click="changeTeacherSelected(studentclass)" small>Apply Changes</v-btn>
													</v-row>

												</v-card>
											</v-dialog>

											<v-dialog v-model="changeTeacherDialog2" persistent max-width="900" max-height="500">
												<template v-slot:activator="{ on }">
													<span @click="changeTeacher(studentclass)"><u>{{studentclass['tutor']['mega_name']}}</u></span>
												</template>
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
																						<td>{{studentclass['schedule']['classid']}}</td>
																						<td>{{studentclass['schedule']['applicable_days']}}</td>
																						<td>{{getSchedule(studentclass)}}</td>
																						<td>{{studentclass['schedule']['minute']}} minutes</td>
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
																<center>We cannot find another teacher for the same time. Please choose another time, and choose another teacher.</center>
															</v-alert>
														</v-col>
													</v-row>

													<v-row>
														<v-col cols="4" class="pt-0">
															<v-menu v-model="menu" :close-on-content-click="false" transition="scale-transition" offset-y full-width max-width="290px" min-width="290px">
																<template v-slot:activator="{ on }">
																	<v-text-field outlined disabled v-model="computedDateFormatted" label="Start Date" placeholder="MM/DD/YYYY format" v-on="on"></v-text-field>
																</template>
																<v-date-picker v-model="date" disabled no-title @input="menu = false"></v-date-picker>
															</v-menu>
														</v-col>
														<v-col cols="4" class="pt-0" align="center">
															<v-select :items="hourLists" v-model="hour" label="Hour" outlined></v-select>
														</v-col>
														<v-col cols="4" class="pt-0" align="center">
															<v-select :items="minuteLists" v-model="minute" label="Minute" outlined></v-select>
														</v-col>
														<v-col cols="4">
															<v-btn color="success" @click="changeTeachernTimeAvailable(studentclass)">Check Available Teacher</v-btn>
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
														<v-btn class="mr-2" @click="changeTeacherDialog2 = false" small>Cancel</v-btn>
														<v-btn class="mr-3" color="primary" @click="changeTeachernTimeSelected(studentclass)" small>Apply Changes</v-btn>
													</v-row>

												</v-card>
											</v-dialog>
										</td>
										<td>
											<v-dialog v-model="classCancellationDialog" width="600">
												<template v-slot:activator="{ on }">
													<button  @click = "cancelClass(studentclass)" class="ml-2 v-btn v-btn--depressed theme--light" style="background-color:#E91E63" icon>
														<v-icon color="#F8BBD0" @click = "cld(studentclass)">event_busy</v-icon>
													</button>
												</template>
												<v-card>
													<v-container>
														<v-row>
															<v-card-title>Class Cancellation</v-card-title>
														</v-row>
														<v-row>
															<v-col cols="6">
																<v-date-picker :min = "getMin(studentclass)" :max="getMax(studentclass)" :allowed-dates = "allowedDatesMakeup" v-model="cancelDate"></v-date-picker>
															</v-col>
															<v-col cols="6" align-self="stretch">

																<v-row class="mb-2">
																	<v-card height="90" width="100%" flat class="text-center white--text mr-2" color="warning">
																		<div style="vertical-align:middle;height:100%;display: flex; ">
																				<p style="margin: auto;">
																					Please pick the class date.
																				</p>
																		</div>
																	</v-card>
																</v-row>
																<div style="height:65%;">
																	<div>
																		<v-row>
																			<v-col cols="7">Schedule</v-col>
																			<v-col cols="5">Teacher</v-col>
																		</v-row>
																		<v-row>
																			<v-col cols="7">{{cancelDate}}, {{getClassHour(studentclass)}} </v-col>
																			<v-col cols="5">{{studentclass['tutor']['mega_name'].charAt(0).toUpperCase() + studentclass['tutor']['mega_name'].slice(1) }}</v-col>
																		</v-row>
																	</div>
																</div>
																<div>
																	<v-row>
																		<v-spacer></v-spacer>
																		<v-btn color="white" class="mr-2" @click="classCancellationDialog = false">Discard</v-btn>
																		<v-btn color="primary" class="mr-2" @click="cancelDialog = true">Confirm</v-btn>
																	</v-row>
																</div>
															</v-col>
														</v-row>
													</v-container>
												</v-card>

												<v-dialog v-model="cancelDialog" width="550">
													<v-card color="#fffece">
														<v-container>
														<v-row class="mb-3 pl-2">
															Are you sure you want to CANCEL {{studentclass['schedule']['date']}}, {{getClassHour(studentclass)}} class with {{studentclass['tutor']['mega_name'].charAt(0).toUpperCase() + studentclass['tutor']['mega_name'].slice(1) }}?
														</v-row>
														<v-row class="mx-2">
															<v-spacer></v-spacer>
															<v-btn color="white" class="mr-2" @click="cancelDialog=false">No</v-btn>
															<v-btn color="primary" @click="makeUpClass(studentclass)">Yes</v-btn>
														</v-row>
													</v-container>
													</v-card>
												</v-dialog>


												<v-dialog v-model="makeUpClassDialog">
																	<v-card class="pa-4">
																		<v-card-title class="headline" style="background-color:#E0E0E0;">Set Make up Class</v-card-title>
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
																											<td>{{studentclass['schedule']['classid']}}</td>
																											<td>{{studentclass['schedule']['applicable_days']}}</td>
																											<td>{{getSchedule(studentclass)}}</td>
																											<td>{{studentclass['schedule']['minute']}} minutes</td>
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
																					<center>Your class will be canceled and you have to set a Make Up schedule.</center>
																				</v-alert>
																			</v-col>
																		</v-row>

																		<v-row>
																			<v-col cols="3" class="pt-0">
																				<v-menu v-model="menu" :close-on-content-click="false" transition="scale-transition" offset-y full-width max-width="290px" min-width="290px">
																					<template v-slot:activator="{ on }">
																						<v-text-field outlined v-model="computedDateFormatted" label="Start Date" placeholder="MM/DD/YYYY format" v-on="on"></v-text-field>
																					</template>
																					<v-date-picker @change="setDate()" :min="getMin(studentclass)" :max="getMax(studentclass)" :allowed-dates="allowedDatesMakeup" v-model="date" no-title @input="menu = false"></v-date-picker>
																				</v-menu>
																			</v-col>
																			<v-col cols="3" class="pt-0" align="center">
																				<v-select :items="hourLists" v-model = "hour" label="Hour" outlined></v-select>
																			</v-col>
																			<v-col cols="3" class="pt-0" align="center">
																				<v-select :items="minuteLists"  v-model = "minute" label="Minute" outlined></v-select>
																			</v-col>
																			<v-col cols="3">
																				<v-btn color="success" @click="getMakeUpClassAvailableTutors(studentclass)">Check Available Teacher</v-btn>
																			</v-col>
																		</v-row>

																		<v-row class="mb-4 mx-1">
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
																			<v-btn class="mr-2"  @click = "makeUpClassDialog = false, cancelDialog  = false, classCancellationDialog = false "small>Discard</v-btn>
																			<v-btn class="mr-3" color="primary" :disabled="makeUpClassTutorSelected" small @click="makeUpClassSummaryDialog = true">Set Make up Class</v-btn>
																		</v-row>

																	</v-card>
																</v-dialog>

																<v-dialog v-model="makeUpClassSummaryDialog" width="550">
																	<v-card class="pa-2">

																		<v-card flat color="#cccccc">
																			<v-container>
																				<v-row class="px-3">
																					<v-col>Cancel</v-col>
																					<v-col class="text-center">{{cancelDate}}, {{getClassHour(studentclass)}}  </v-col>
																					<v-col class="text-center">{{studentclass['tutor']['mega_name'].charAt(0).toUpperCase() + studentclass['tutor']['mega_name'].slice(1) }}</v-col>
																				</v-row>
																			</v-container>
																		</v-card>
																		<v-card flat color="success" class="mb-3">
																			<v-container>
																				<v-row class="px-3">
																					<v-col>Make Up Class</v-col>
																					<v-col class="text-center">{{date}}, {{getHour()}}</v-col>
																					<v-col class="text-center">{{selectedTutor['mega_name'] }}</v-col>
																				</v-row>
																			</v-container>
																		</v-card>
																		<v-container>
																			<v-row>
																				<v-spacer></v-spacer>
																				<v-btn class="mr-2" color="white" @click="makeUpClassSummaryDialog = false, makeUpClassDialog = false, cancelDialog = false">Discard</v-btn>
																				<v-btn color="primary" @click = "setMakeUpClass(studentclass)">Confirm</v-btn>
																			</v-row>
																		</v-container>

																	</v-card>
																</v-dialog>


											</v-dialog>


											<button  class="ml-2 v-btn v-btn--depressed theme--light" style="background-color:#E91E63" icon>
												<v-icon color="#F8BBD0">headset</v-icon>
											</button>
											<button class="ml-2 v-btn v-btn--depressed theme--light" style="background-color:#E91E63" icon>
												<v-icon color="#F8BBD0">trending_up</v-icon>
											</button>
											<button class="ml-2 v-btn v-btn--depressed theme--light" style="background-color:#E91E63" icon>
												<v-icon color="#F8BBD0">cached</v-icon>
											</button>
										</td>
									</tr>
								</tbody>
							</template>
						</v-simple-table>
					</v-container>
				</v-row>
			</v-card>

		</v-tab-item>


		<v-tab-item>b</v-tab-item>
		<v-tab-item>c</v-tab-item>


	</v-tabs>




</v-row>
</v-container>
</template>

<script>
import axios from 'axios'
import moment from 'moment'
export default {


	props: ['studentClass', 'student'],


	data() {
		return {


			isSetPhone: true,
			isSetEmail: true,
			isSetRecordings: true,
			isSetTakeOver: true,
			isEdit: false,
			isEditButton: true,
			datesAllowed: [],
			cancelDate: new Date().toISOString().substr(0, 10),
			cancelDateSelected: new Date().toISOString().substr(0, 10),

			availableDates: [],
			availableTutorLoading: false,
			classCancellationDialog:false,
			cancelDialog: false,
			makeUpClassDialog: false,
			makeUpClassSummaryDialog: false,

			TutorsAvailable: [],

			makeUpClassTutorSelected: true,

			hourLists: ['5:00', '6:00', '7:00', '8:00', '9:00', '10:00', '11:00',
			'12:00', '13:00', '14:00', '15:00', '16:00', '17:00', '18:00',
			'19:00', '20:00', '21:00', '22:00', '23:00'
		],
		minuteLists: ['00', '10', '20', '30', '40', '50'],

		changeTeachernTimeClassStart: [],
		changeTeachernTimeClassEnd: [],


		currentStudent: [],

		changeTimeVerifyTeacher: false,
		changeTeacherVerify: false,

		changeTimeTeacherAvailable: true,
		changeTeacherSameTime: false,
		selectedTutor: '',
		changeTimeDialog1: false,
		changeTimeDialog2: false,
		changeTeacherDialog1: false,
		changeTeacherDialog2: false,
		minute: '',
		hour: '',
		minutes: [],
		timeDuration: [],
		dateWarning: [],

		date: new Date().toISOString().substr(0, 10),
		dateFormatted: this.formatDate(new Date().toISOString().substr(0, 10)),
		menu: false,
		time: ['1:00', '2:00', '3:00', '4:00']

	}
},

mounted() {

	console.log(this.studentClass, 'ssu')

	console.log(this.student[0], 'sstudent')



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

	selectedTutor(oldval, newval){



	this.makeUpClassTutorSelected = this.selectedTutor ? false : true


	console.log(this.selectedTutor)
	}
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


	editStudent() {
		this.isSetPhone = false
		this.isSetEmail = false
		this.isSetRecordings = false
		this.isSetTakeOver = false
		this.isEdit = true
		this.isEditButton = false

		console.log(student)
	},

	updateStudent(student){

		if(student){

			console.log(student, 'student')
			const form = new FormData()
			form.append('email', student.email)
			form.append('phone_number', student.phone_number)
			form.append('recordings', student.recordings)
			form.append('takeover', student.takeover)
			form.append('conn_id', student.conn_id)



			axios.post('Regularclass/softUpdate', form).then(res => {



				console.log(res.data, 'adsada')

this.cancel()
			})


		}




	},

	cancel() {
		this.isSetPhone = true
		this.isSetEmail = true
		this.isSetRecordings = true
		this.isSetTakeOver = true
		this.isEdit = false
		this.isEditButton = true

	},

	getContract(studentclass) {

		let class_start = studentclass['schedule']['class_start'].split(",")[0].split(" ")



		let class_end = studentclass['schedule']['class_end'].split(",")

		class_end = studentclass['schedule']['class_end'].split(",")[class_end.length - 1].split(" ")

		console.log(class_start[0].substr(1))
		console.log(class_end[0])


		return class_start[0].substr(1) + " - " + class_end[0]
	},

	getMin(studentclass) {

		let class_start = studentclass['schedule']['class_start'].split(",")[0].split(" ")

		return class_start[0].substr(1)
	},

	getMax(studentclass) {

		let class_end = studentclass['schedule']['class_end'].split(",")

		class_end = studentclass['schedule']['class_end'].split(",")[class_end.length - 1].split(" ")

		return class_end[0]
	},

	getAllowedDates() {

		let class_end = this.currentStudent['schedule']['class_end'].split(",")

		let classes = []

		class_end.forEach(data => {
			let split = data.split(" ")
			classes.push(split[0])
		})


		if (classes[0].charAt(0) === '"') {
			classes[0] = classes[0].substr(1)
		}


		return classes

	},





	allowedDates(val) {
		return this.getAllowedDates().includes(val)
	},



	getAllowedDatesMakeUp(){


		let class_end = this.currentStudent['schedule']['class_end'].split(",")

		let classes = []

		class_end.forEach(data => {
			let split = data.split(" ")
			classes.push(split[0])
		})


		if (classes[0].charAt(0) === '"') {
			classes[0] = classes[0].substr(1)
		}


		let cancelled_class = []
		let fillArray = []


			let Studentclasses = JSON.parse(this.currentStudent['tutor']['class_schedule'])

		Studentclasses.forEach(data => {



				if(data['schedule']['classid'] === this.currentStudent['schedule']['classid'] ){

			fillArray = data['cancelled_class']
				}
			})

			if(fillArray){

			fillArray.forEach(data => {

				cancelled_class.push(data.split(" ")[0])
			})
}


				if(cancelled_class.length > 0){

						cancelled_class.forEach(data => {

							console.log(data , 'tt')


							let getIndex = classes.findIndex(check => check === data)




						if(getIndex >=0){

								classes.splice(getIndex, 1)
						}
						})
				}

				console.log(classes[0], 'ttt')



		return classes



	},


	allowedDatesMakeup(val){

			return this.getAllowedDatesMakeUp().includes(val)
	},






	getSchedule(schedule) {
		schedule = schedule['schedule']['class_start'].split(",")[0].split(" ")
		return schedule[1]
	},

	setDate() {

		let datesArray = []

		let selectedDate = this.date

		Object.keys(this.availableDates['start']).forEach(getdate => {

			let currentDate = moment(this.availableDates['start'][getdate]).format('YYYY-MM-DD')

			if (currentDate === selectedDate) {

				datesArray.push(getdate)
			}
		})

		let start = parseInt(this.currentStudent['tutor']['start_am'])
		let end = parseInt(this.currentStudent['tutor']['end_pm'])

		let tutorSchedule = []

		for (var i = start; i <= end; i++) {

			tutorSchedule.push(i)
		}


		let startDate = this.availableDates['start']
		let endDate = this.availableDates['end']
		let time = []
		let timeDuration = []


		let startDateLength = Object.keys(startDate).length
		for (var i = datesArray[0]; i < startDateLength; i++) {

			let currentTime = moment(startDate[i]).format('H')

			let start = moment(startDate[i]).format('mm')


			timeDuration.push({
				hour: currentTime,
				duration: start
			})
			let index = time.indexOf(currentTime)

			if (index === -1 && currentTime !== 'Invalid date' && currentTime !== '0') {
				time.push(currentTime)
			}


			this.time = time
			this.timeDuration = timeDuration
		}

		console.log(time, 'time')
		console.log(timeDuration)

	},

	setMinutes() {
		console.log(this.hour, 'minute')
		console.log(this.timeDuration, 'duration')

		let durations = this.timeDuration.filter(data => parseInt(data.hour) === parseInt(this.hour))
		console.log(this.minutes, 'minutes')
		console.log(durations, 'durations')
		let arr = durations.map(JSON.stringify).reverse() // convert to JSON string the array content, then reverse it (to check from end to begining)
		.filter(function(item, index, arr) {
			return arr.indexOf(item, index + 1) === -1;
		}) // check if there is any occurence of the item in whole array
		.reverse().map(JSON.parse) // revert it to original state

		let extract = arr.map(x => x.duration)

		let findExtra = extract.findIndex((data, index, arr) => {

			if (arr[index + 1]) {

				if (arr[index + 1] < arr[index]) {

					return index
				}
			}
		})

		console.log(findExtra, 'datas')

		if (findExtra >= 0) {
			let changePosition = extract.splice(findExtra + 1)
		}

		console.log(extract, 'filter')
		let selectedDate = this.date + ' '
		let selectedHour = this.hour

		let warningMinutes = []

		for (var i = 0; i < extract.length; i++) {
			let timeFormat = moment({
				hour: selectedHour,
				minute: extract[i]
			}).format('HH:mm:ss')

			let dateFormat = selectedDate + timeFormat

			let getIndex = this.dateWarning['start'].findIndex(data => data === dateFormat)


			if (getIndex > -1) {
				extract[i] = ({
					text: String(extract[i]) + ' - warning',
					value: extract[i]
				})
			}

		}

		if (extract.length) {
			this.minutes = extract
		}

	},


	availableTeacher(studentclass) {

		this.availableTutorLoading = true

		this.currentStudent = studentclass

		let start = parseInt(studentclass['tutor']['start_am'])
		let end = parseInt(studentclass['tutor']['end_pm'])

		let tutorSchedule = []

		for (var i = start; i <= end; i++) {

			tutorSchedule.push(i)
		}

		let class_end = studentclass['schedule']['class_end'].split(",")



		let classes = []

		class_end.forEach(data => {

			let split = data.split(" ")

			classes.push(split[0])
		})

		let dates = classes

		let startDates = []
		let endDates = []
		let test = ''
		let test2 = ''
		dates.forEach(myDate => {

			tutorSchedule.forEach(hour => {

				let minutes = 0

				for (var i = 0; i <= 5; i++) {


					var mom = moment({
						hour: hour,
						minute: minutes
					}).format('HH:mm:ss')


					let date = myDate + ' '
					test = date
					let add = moment(mom, 'HH:mm:ss').add(parseInt(studentclass['schedule']['duration']), 'minutes').format('HH:mm:ss')

					let start_date = date + mom

					let end_date = date + add

					startDates.push(start_date)
					endDates.push(end_date)

					minutes += 10

				}
			})
		})


		var mom = moment({
			hour: 24,
			minute: 0
		}).format('HH:mm:ss')

		console.log(startDates, 'start')
		console.log(endDates, 'end')

		let weekdays = studentclass['schedule']['applicable_days']


		console.log(weekdays)


		const form = new FormData()

		form.append('weekdays', weekdays)
		form.append('start_class', startDates)
		form.append('end_class', endDates)
		form.append('tutor', JSON.stringify(studentclass['tutor']))

		axios.post('Tutor/checkTeacherSchedule', form).then(res => {

			console.log(res.data)

			const start = res.data.start
			const end = res.data.end
			const dateWarning = res.data.dateWarning


			this.availableDates = {
				start: start,
				end: end
			}
			this.dateWarning = dateWarning

			console.log(end, 'avail')
			let time = []
			let timeDuration = []
			let startDate = this.availableDates['start']
			this.date = moment(startDate[0]).format('YYYY-MM-DD')

			let startDateLength = Object.keys(this.availableDates['start']).length
			for (var i = 0; i < startDateLength; i++) {

				let currentTime = moment(startDate[i]).format('H')


				let start = moment(startDate[i]).format('mm')

				timeDuration.push({
					hour: currentTime,
					duration: start
				})

				let index = time.indexOf(currentTime)


				if (index === -1 && currentTime !== 'Invalid date' && currentTime !== '0') {
					time.push(currentTime)
				}

			}
			this.time = time
			this.timeDuration = timeDuration

			let checkData = setInterval(() => {

				if (this.availableDates && this.time.length && this.timeDuration) {
					this.availableTutorLoading = false;
					this.changeTimeDialog1 = true
					clearInterval(checkData)
				}
			}, 1000)
		})

	},

	changeTime(studentclass) {


		const getDates = this.getAllowedDates()
		const getMinute = this.minute
		const getHour = this.hour
		const date = this.date
		console.log(getDates, 'available')
		console.log(getHour, 'hour')
		console.log(getMinute, 'minute')



		let getCurrentSelectedDate = getDates.findIndex(data => data.toString() === date.toString())
		let classStart = []
		let classEnd = []
		let testData = ''
		console.log(this.currentStudent, 'current')
		if (getCurrentSelectedDate >= 0) {

			for (var i = getCurrentSelectedDate; i < getDates.length; i++) {

				var mom = moment({
					hour: getHour,
					minute: getMinute
				}).format('HH:mm:ss')

				let selectedDate = getDates[i] + ' '
				let add = moment(mom, 'HH:mm:ss').add(parseInt(this.currentStudent.schedule.duration), 'minutes').format('HH:mm:ss')
				let start_date = selectedDate + mom

				let end_date = selectedDate + add


				classStart.push(start_date)
				classEnd.push(end_date)
			}


			if(classStart[0].split(' ')[0].charAt(0) === '"'){

					classStart[0] =  classStart[0].substr(1)
			}

			if(classEnd[0].split(' ')[0].charAt(0) === '"'){

					classEnd[0] =  classEnd[0].substr(1)
			}

			classStart = JSON.stringify(classStart).replace(/"/g, '').replace('[', "").replace(']', "")

		classEnd = JSON.stringify(classEnd).replace(/"/g, '').replace('[', "").replace(']', "")

		}


		console.log(testData, 'testdata')
		let getCurrentDate = moment().format('YYYY-MM-DD')
		let dateStart = classStart[0].split(",")[0].split(" ")[0]
		let classid = studentclass['schedule']['classid']
		let tutor = studentclass['tutor']
		studentclass['schedule']['class_start'] = classStart
		studentclass['schedule']['class_end'] = classEnd

		const form = new FormData()
		form.append('dateStart', dateStart)
		form.append('classid', classid)
		form.append('tutor', tutor['idx'])
		form.append('class_start', classStart)
		form.append('class_end', classEnd)
		form.append('classInformation', studentclass)
		form.append('currentDate', getCurrentDate)
		form.append('hour', getHour)
		form.append('minute', getMinute)
		form.append('classInformation', JSON.stringify(studentclass))


		axios.post('Tutor/changeTime', form).then(res => {

			console.log(res.data)
			if (res.data.success) {

				location.reload()
			}

			console.log(res.data, 'ress')

		})
		console.log(getCurrentDate, 'current')
		console.log(classid, 'classid')
		console.log(tutor['idx'], 'tutor')
		console.log(dateStart, 'dateStart')
		console.log(classStart, 'startDate')
		console.log(classEnd, 'endDate')

	},


	changeTeacher(studentclass) {

		this.availableTutorLoading = true
		console.log(studentclass['schedule'], 'test')

		const form = new FormData()


		form.append('start_class', studentclass['schedule']['class_start'])
		form.append('end_class', studentclass['schedule']['class_end'])
		form.append('weekdays', JSON.parse(studentclass['schedule']['applicable_days']))
		form.append('tutor', studentclass['tutor']['idx'])

		axios.post('Tutor/changeTeacher', form).then(res => {

			console.log(res.data, 'teacher')

			if (res.data) {

				this.$set(this.$data, 'TutorsAvailable', res.data)

				let checkData = setInterval(() => {

					if (this.TutorsAvailable) {
						this.availableTutorLoading = false;
						this.changeTeacherVerify = true
						this.changeTeacherSameTime = true
						this.changeTeacherDialog1 = true
						clearInterval(checkData)
					}
				}, 1000)
			} else {
				this.availableTutorLoading = false;
				this.changeTeacherDialog2
			}

		})


	},

	changeTeacherSelected(studentclass) {

		const form = new FormData()

		let cancelled_class = []

			let classes = JSON.parse(studentclass['tutor']['class_schedule'])

			classes.forEach(data => {



				if(data['schedule']['classid'] === studentclass['schedule']['classid'] ){

			cancelled_class = data['cancelled_class']
				}
			})




		form.append('tutoridx', studentclass['tutor']['idx'])

		form.append('classData', JSON.stringify(studentclass['schedule']))

		form.append('cancelledClass', JSON.stringify(cancelled_class))

		form.append('selectedTutorIdx', this.selectedTutor['idx'])


		axios.post('Tutor/changeTeacherSelected', form).then(res => {

			if (res.data.success1 && res.data.success2) {

				location.reload()
			}
			console.log(res.data, 'res')
		})


	},

	changeTeachernTimeAvailable(studentclass) {

		console.log('see')
		let class_start = studentclass['schedule']['class_start'].split(',')
		let class_end = studentclass['schedule']['class_end'].split(',')

		if (class_start[0].split(' ')[0].charAt(0) === '"') {

			class_start[0] = class_start[0].substr(1)
		}

		if (class_end[0].split(' ')[0].charAt(0) === '"') {

			class_end[0] = class_end[0].substr(1)
		}



		let minute = this.minute
		let hour = this.hour

		let startTime = moment({
			hour: this.hour,
			minute: this.minute
		}).format('HH:mm:ss')
		let endTime = moment(startTime, 'HH:mm:ss').add(parseInt(studentclass['schedule']['duration']), 'minutes').format('HH:mm:ss')


		let start_class = []
		let end_class = []

		for (var i = 0; i < class_start.length; i++) {

			let startDate = class_start[i].split(' ')[0] + ' '
			let endDate = class_end[i].split(' ')[0] + ' '


			start_class.push(startDate + startTime)
			end_class.push(endDate + endTime)

		}

		this.changeTeachernTimeClassStart = start_class
		this.changeTeachernTimeClassEnd = end_class

		let weekdays = studentclass['schedule']['applicable_days']
		const form = new FormData()

		form.append('start_class', start_class)
		form.append('end_class', end_class)
		form.append('weekdays', weekdays)

		axios.post('Tutor/changeTeachernTimeAvailable', form).then(res => {

			if (res.data) {
				console.log(res.data)

				this.changeTeacherVerify = true
				this.$set(this.$data, 'TutorsAvailable', res.data)


			}
		})

	},

	changeTeachernTimeSelected(studentclass) {

		const form = new FormData()

		studentclass['schedule']['class_start'] = JSON.stringify(this.changeTeachernTimeClassStart).replace(/"/g, '').replace('[', "").replace(']', "")

		studentclass['schedule']['class_end'] = JSON.stringify(this.changeTeachernTimeClassEnd).replace(/"/g, '').replace('[', "").replace(']', "")


		let cancelled_class = []

			let classes = JSON.parse(studentclass['tutor']['class_schedule'])

			classes.forEach(data => {


				if(data['schedule']['classid'] === studentclass['schedule']['classid'] ){

			cancelled_class = data['cancelled_class']
				}
			})


		form.append('tutoridx', studentclass['tutor']['idx'])

		form.append('classData', JSON.stringify(studentclass['schedule']))

		form.append('selectedTutorIdx', this.selectedTutor['idx'])

		form.append('cancelledClass', JSON.stringify(cancelled_class))

		axios.post('Tutor/changeTeachernTimeSelected', form).then(res => {

			if (res.data.success1 && res.data.success2) {

				location.reload()
			}

			console.log(res.data)
		})
		console.log(studentclass, 'class')

	},

	getClassHour(studentclass){

		let hour = moment({hour: studentclass['schedule']['hour']}).format('HH:mm:ss')

		return hour
	},

	cancelClass(studentclass){

		console.log(this.currentStudent, 'student')

		this.currentStudent = studentclass




		this.cancel()
	},

makeUpClass(studentclass){

		this.TutorsAvailable = []
	this.makeUpClassDialog = true
},

getMakeUpClassAvailableTutors(studentclass){


	var mom = moment({hour: this.hour, minute:this.minute}).format('HH:mm:ss')
	let date  = this.date + ' '

	let add = moment(mom, 'HH:mm:ss').add(parseInt(studentclass['schedule']['duration']), 'minutes').format('HH:mm:ss')
	let start_date =  date + mom

	let end_date = date + add


		const form = new FormData()

let weekdays = studentclass['schedule']['applicable_days']
		form.append('start_class', start_date)
		form.append('end_class', end_date)
		form.append('weekdays', weekdays)



		axios.post('Tutor/getMakeUpClassAvailableTutors', form).then(res => {


		if(res.data){



				this.$set(this.$data, 'TutorsAvailable', res.data)
		}
		})

},



getHour(){

	return moment({hour: this.hour, minute: this.minute}).format('HH:mm:ss')
},

setMakeUpClass(studentclass){

	var mom = moment({hour: this.hour, minute:this.minute}).format('HH:mm:ss')
	let date  = this.date + ' '

	let add = moment(mom, 'HH:mm:ss').add(parseInt(studentclass['schedule']['duration']), 'minutes').format('HH:mm:ss')
	let start_date =  date + mom

	let end_date = date + add


 let cancel_end = moment(mom, 'HH:mm:ss').add(parseInt(this.minute), 'minutes').format('HH:mm:ss')

 let cancelTime = moment({hour: studentclass['schedule']['hour'], minute:studentclass['schedule']['minute']}).format('HH:mm:ss')
 let cancelAdd =  moment(cancelTime, 'HH:mm:ss' ).add(parseInt(studentclass['schedule']['duration']), 'minutes').format('HH:mm:ss')


	let cancelDateStart = this.cancelDate + ' ' + cancelTime
	let cancelDateEnd = this.cancelDate + ' ' + cancelAdd


	let selectedTutorIdx = this.selectedTutor['idx']
	let tutorIdx = studentclass['tutor']['idx']

	let classData = studentclass



	const form = new FormData()

	form.append('cancelDateStart', cancelDateStart)
	form.append('cancelDateEnd', cancelDateEnd)
	form.append('makeUpDate', date)
	form.append('start_class', start_date)
	form.append('end_class', end_date)
	form.append('classData', JSON.stringify(classData))
	form.append('hour', this.hour)
	form.append('minute', this.minute)

	form.append('selectedTutorIdx', selectedTutorIdx)
	form.append('tutorIdx', tutorIdx)
	form.append('classid', studentclass['schedule']['classid'])

	axios.post('Tutor/setMakeUpClass', form).then(res => {

		if (res.data.success1 && res.data.success2) {

			location.reload()
		}
		console.log(res.data, 'res')
	})

	console.log(classData, selectedTutorIdx, tutorIdx)



},

cld(studentclass){

	this.currentStudent = studentclass



	console.log(studentclass, 'ss')
	this.classCancellationDialog = true
}








},

}
</script>

<style scoped lang="css">

</style>
