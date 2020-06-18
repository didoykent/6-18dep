<template >
<v-app>
	<v-row>
		<v-row class="mx-5 my-5" >

			<v-col cols="3">
				<v-img src="https://image.flaticon.com/icons/svg/265/265674.svg" lazy-src="https://image.flaticon.com/icons/svg/265/265674.svg" aspect-ratio="1" class="grey lighten-2" max-width="300"
				  max-height="300">
					<v-row align="end" justify="end" class="lightbox white--text pa-2 fill-height">
							<v-btn class="mx-2" fab dark small color="cyan">
								<v-icon dark>mdi-camera-account</v-icon>
							</v-btn>
	        </v-row>
				  </v-img>
			</v-col>

			<v-col cols="9">

				<v-row class="headline">
					Personal Information
				</v-row>



				<v-row class="pb-0">
					<v-col cols="12" sm="6" md="3" class="pb-0">
						<v-text-field class="pb-0" label="Mega Name" v-model = "Tutor.mega_name" placeholder="Mega Name" outlined></v-text-field>
					</v-col>
					<v-col cols="12" sm="6" md="3" class="pb-0">

							<v-select v-model = "Tutor.position" :items="Positions" label="Position" outlined></v-select>

					</v-col>
					<v-col cols="12" sm="6" md="3" class="pb-0">
						<v-text-field class="pb-0" label="First Name" v-model = "Tutor.first_name" placeholder="First Name" outlined></v-text-field>
					</v-col>
					<v-col cols="12" sm="6" md="3" class="pb-0">
						<v-text-field class="pb-0" label="Last Name"  v-model = "Tutor.last_name" placeholder="Last Name" outlined></v-text-field>
					</v-col>
				</v-row>

				<v-row class="py-0">
					<v-col cols="12" sm="6" md="3" class="personal py-0">
						<v-text-field label="Sex" v-model = "Tutor.sex" placeholder="Sex" outlined></v-text-field>
					</v-col>
					<v-col cols="12" sm="6" md="3" class="personal py-0">
						<v-text-field label="Date of Birth"  v-model = "Tutor.date_of_birth" placeholder="Date of Birth" outlined></v-text-field>
					</v-col>
					<v-col cols="12" sm="6" md="3" class="personal py-0">
						<v-text-field label="Mobile Number" v-model = "Tutor.mobile_number" placeholder="Mobile Number" outlined></v-text-field>
					</v-col>
					<v-col cols="12" sm="6" md="3" class="personal py-0">
						<v-text-field label="Email"   :rules='emailRules' v-model= "Tutor.email" placeholder="Email" outlined></v-text-field>
					</v-col>
				</v-row>

				<v-row class="py-0">
					<v-col cols="12" lg="12" class="py-0">
						<v-text-field label="Residential Address"  v-model= "Tutor.address" placeholder="Residential Address" outlined></v-text-field>
					</v-col>
				</v-row>

				<v-row class="py-0 mb-5">
					<v-col cols="12" md="6" class="py-0">
						<v-text-field label="Major" v-model= "Tutor.major" placeholder="Major" outlined></v-text-field>
					</v-col>
					<v-col cols="12" md="6" class="py-0">
						<v-text-field label="School" v-model= "Tutor.school" placeholder="School" outlined></v-text-field>
					</v-col>
				</v-row>



				<v-row class="headline">
					Work Experience
				</v-row>

				<v-row class="pb-0">

					<template v-for = "(row, index) in rowCount">
					<v-col cols="12" sm="6" md="3" class="pb-0">
						<v-text-field label="Position"  v-model= "workPosition[index]" placeholder="Position" outlined></v-text-field>
					</v-col>
					<v-col cols="12" sm="6" md="3" class="pb-0">
						<v-text-field label="Company Name" v-model= "workCompany[index]" placeholder="Company Name" outlined></v-text-field>
					</v-col>
					<v-col cols="12" sm="6" md="3" class="pb-0">
						<v-text-field label="From"  v-model= "workStart_date[index]" placeholder="From" outlined></v-text-field>
					</v-col>
					<v-col cols="12" sm="6" md="3" class="pb-0">
						<v-text-field label="To" v-model= "workEnd_date[index]" placeholder="To" outlined></v-text-field>
					</v-col>

					</template>
				</v-row>

				<v-row class="pb-0" v-for="(row, index) in rows" :key="index">
					<component class="pb-0" :is="row" :key="row.name"></component>
				</v-row>

				<v-row class="px-0 mb-12">
					<v-col class="py-0">
						<v-btn tile outlined block depressed medium text color="primary" @click="addRow">
							<v-icon>mdi-plus</v-icon> Add
						</v-btn>
					</v-col>
				</v-row>



				<v-row class="headline mb-4">
					Introduction
				</v-row>

				<v-row>
					<v-col cols="12" md="12" class="py-0">
						<v-textarea outlined name="input-7-4" label="Introduction" v-model= "Tutor.introduction" placeholder="Introduce yourself as a teacher here"></v-textarea>
					</v-col>
				</v-row>
				<v-row>
					<v-col cols="12" sm="12" class="pb-0">
						<v-text-field label="Specialty" v-model= "Tutor.specialty" placeholder="Specialty" outlined></v-text-field>
					</v-col>
				</v-row>
				<v-row>
					<div class="my-2">
						<v-file-input

						v-if= "Tutor.position && Tutor.position !== 'Kr_manager'"
			v-model="files"
			color="deep-purple accent-4"
			counter
			label="File input"
			placeholder="Select your files"
			prepend-icon="mdi-upload"

			outlined
			:show-size="1000"

		>
			<template v-slot:selection="{ index, text }">
				<v-chip
					v-if="index < 2"
					color="deep-purple accent-4"
					dark
					label
					small
				>
					{{ text }}
				</v-chip>

				<span
					v-else-if="index === 2"
					class="overline grey--text text--darken-3 mx-2"
				>
					+{{ files.length - 2 }} File(s)
				</span>
			</template>
		</v-file-input>
					</div>


				</v-row>
				<v-row>
					<v-spacer></v-spacer>
					<div class="my-2">
						<v-btn color="primary"  :disabled = "!verifyRequiredValues" @click="save()">Save and Proceed</v-btn>
					</div>

				</v-row>



			</v-col>
		</v-row>
	</v-row>

	<v-dialog v-model="krAdminDialog" max-width="750" max-height="500">
		<div class="d-flex justify-content-center align-items-center" style="height:50px;width:50px;
		background-color:#e91e63;z-index:2;position:absolute;left:29%">
			<v-icon color="white" x-large>account_circle</v-icon>
		</div>
			<v-card class="mt-4 pa-4">
				<v-card-title class="mt-2">Schedule</v-card-title>
				<v-container>
					<v-row>
						<v-col cols="12" sm="4">
							<v-menu v-model="menu" :close-on-content-click="false" transition="scale-transition" offset-y full-width max-width="290px" min-width="290px">
								<template v-slot:activator="{ on }">
									<v-text-field  v-model="computedDateFormatted" label="Date" placeholder="MM/DD/YYYY format" v-on="on"></v-text-field>
								</template>
								<v-date-picker v-model="date" no-title @input="menu = false"></v-date-picker>
							</v-menu>
						</v-col>
						<v-col cols="12" sm="2">
								<v-select v-model = "Tutor.start_am" :items="starts" label="From"></v-select>
						</v-col>
						<v-col cols="12" sm="2">
								<v-select v-model = "Tutor.end_pm" :items="ends" label="To"></v-select>
						</v-col>
						<v-col cols="12" sm="4">
							<v-select v-model = "Tutor.team" :items="teams" label="Team"></v-select>
						</v-col>
					</v-row>
						<v-card-title class="mt-2" style="font-size: 1.25rem;font-weight: 500;letter-spacing: .0125em;">Log in</v-card-title>
						<v-row>
							<v-col cols="12" sm="4">
								<v-text-field v-model = "Tutor.id" label="ID"></v-text-field>
							</v-col>
							<v-col cols="12" sm="4">
								<v-text-field v-model = "Tutor.pw" label="Password"></v-text-field>
							</v-col>
							<v-col cols="12" sm="4">
								<v-text-field v-model = "Tutor.confirm_password"label="Confirm Password"></v-text-field>
							</v-col>
						</v-row>
						<v-row class="d-flex justify-content-end">
								<v-btn class="white--text" color="#e91e63" @click = "setManager()">Submit</v-btn>
						</v-row>
				</v-container>
			</v-card>
	</v-dialog>


</v-app>
</template>

<script>

import axios from 'axios'


export default {

	data() {
		return {
			 files: [],
			teams: ['Amber', 'Diamond', 'Emerald', 'Onxy', 'None'],
			starts: [7,8,9,10],
			ends: [4,5,6,7],
			date: new Date().toISOString().substr(0, 10),
		dateFormatted: this.formatDate(new Date().toISOString().substr(0, 10)),
		menu: false,
		krAdminDialog: false,
			rowCount: 1,
			Positions: ['Kr_manager', 'Operations_manager', 'Marketing_manager', 'Head_tutor', 'Training_officer', 'Assistant_head_tutor', 'Team_leader', 'Assistant_team_leader', 'Tutor', 'Trainee'],
			rows: [],
			Tutor: [],
			workPosition: [],
			workCompany: [],
			workStart_date: [],
			workEnd_date: [],
			emailRules: [
        v => /.+@.+/.test(v) || "E-mail must be valid"
      ],

			verifyRequiredValues: false

		}
	},

	mounted(){


	},

	computed:{
			computedDateFormatted() {
				return this.formatDate(this.date)
			},
	},

	watch: {

		date(val) {
		this.dateFormatted = this.formatDate(this.date)
	},

		Tutor:{

			handler(oldval, newval){







			if(newval.mega_name && newval.position && newval.first_name && newval.last_name && newval.sex && newval.date_of_birth && newval.mobile_number && newval.email && newval.address && newval.major && newval.school && newval.introduction && newval.specialty && this.workPosition && this.workCompany && this.workStart_date && this.workEnd_date   ){

					this.verifyRequiredValues = true

					console.log(this.verifyRequiredValues)
			}
			else{

				this.verifyRequiredValues = false
			}

		},
		deep: true

		},


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

		addRow() {



			this.rowCount++

		},

		checkFile(){
		const form = new FormData()
		form.append('files', this.files)
		axios.post('Tutor/uploadFile', form).then(res => {

			console.log(res.data, 'res')
		})

		},



		save() {

			if(this.files){

		this.Tutor.files = this.files
			}

			this.Tutor.workexp = []
		for(var i =0; i<this.rowCount; i++){

			this.Tutor.workexp.push('Position: ' + this.workPosition[i] + ' Company: ' + this.workCompany[i] + ' Start date: ' + this.workStart_date[i] +  ' End date: ' + this.workEnd_date[i])
		}

		if(this.Tutor.position === 'Kr_manager'){

			this.krAdminDialog = true
}
else{
		this.$store.dispatch('setTutor', {Tutor: this.Tutor })

}






},

setManager(){

	this.$store.dispatch('setManager', { Tutor: this.Tutor})
}

	},


}
</script>

<style lang="css">
        .fileContainer {
            overflow: hidden;
            position: relative;
        }

        .fileContainer [type=file] {
            cursor: inherit;
            display: block;
            font-size: 999px;
            filter: alpha(opacity=0);
            min-height: 21px;
            min-width: 100%;
            opacity: 0;
            position: absolute;
            right: 0;
            text-align: right;
            top: 0;
        }

        .fileContainer {
            background: #E3E3E3;
            float: left;
            padding: .5em;
            height: 21px;
        }

        .fileContainer [type=file] {
            cursor: pointer;
        }
    </style>
