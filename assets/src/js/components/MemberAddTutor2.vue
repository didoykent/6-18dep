<template>
<v-app>

	<v-row>
		<v-row class="mx-5 my-5" align="stretch">
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
				<v-row class="headline schedule">
					<v-col  sm="12" md="4" class="pb-0">
						Schedule
					</v-col>
					<v-col sm="12" md="4" class="pb-0">
						<v-checkbox label="AM" @change="formChanges" v-model="Tutor2.am" value="1"></v-checkbox>
					</v-col>
					<v-col  sm="12" md="4" class="pb-0">
						<v-checkbox label="PM"@change="formChanges" v-model="Tutor2.pm" value="1"></v-checkbox>
					</v-col>
				</v-row>

				<v-row class="pb-0">
					<v-col cols="12" sm="12" md="2" class="pb-0">
						<v-select :items="places" @change="formChanges"v-model = "Tutor2.workplace" label="Workplace" outlined></v-select>
					</v-col>
					<v-col  sm="6" md="2" class="pb-0">
						<v-menu v-model="menu2" :close-on-content-click="false" transition="scale-transition" offset-y full-width max-width="290px" min-width="290px">
							<template v-slot:activator="{ on }">
								<v-text-field outlined @input="formChanges" v-model="computedDateFormatted" label="Starting Date" placeholder="MM/DD/YYYY format" v-on="on"></v-text-field>
							</template>
							<v-date-picker v-model="date" no-title @input="menu2 = false"></v-date-picker>
						</v-menu>
					</v-col>
					<v-col cols="12" sm="6" md="2" class="pb-0">
						<v-select @change="formChanges"v-model ="Tutor2.start_am":items="start_am" label="Start" outlined></v-select>
					</v-col>
					<v-col cols="12" sm="6" md="2" class="pb-0">
						<v-select @change="formChanges"v-model = "Tutor2.end_am":items="end_am" label="End" outlined></v-select>
					</v-col>
					<v-col cols="12" sm="6" md="2" class="pb-0">
						<v-select @change="formChanges"v-model = "Tutor2.start_pm":items="start_pm" label="Start" outlined></v-select>
					</v-col>
					<v-col cols="12" sm="6" md="2" class="pb-0">
						<v-select @change="formChanges" v-model = "Tutor2.end_pm":items="end_pm" label="End" outlined></v-select>
					</v-col>
				</v-row>

				<v-row class="headline">
					Class Type
				</v-row>

				<v-row class="pb-0">
					<v-col cols="12" sm="12" md="4" class="pb-0">
						<v-select @change="formChanges"v-model = "Tutor2.affiliation" :items="affiliation" label="Affiliation" outlined></v-select>
					</v-col>
					<v-col cols="12" sm="12" md="4" class="pb-0">
						<v-select @change="formChanges" v-model = "Tutor2.language" :items="languages" label="Language" outlined></v-select>
					</v-col>



						<v-col cols="12" sm="12" md="4"  >
								<v-card class="pt-0 px-3">
							<v-row align="center" no-gutters class="type" justify="center" align-content="center">
								Phone
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="Phone" v-model = "classType[0]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="type" align-content="center">
								Video
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="Video" v-model = "classType[1]"></v-checkbox>
							</v-row>
								</v-card>
						</v-col>

				</v-row>


				<v-row class="headline">
					Country
				</v-row>


				<v-row class="pb-0">
					<v-col cols="12" sm="12" md="4" class="pb-0">
						<v-select @change="formChanges"v-model = "Tutor2.country" :items="countries" label="Country" outlined></v-select>
					</v-col>
					<v-col cols="12" sm="12" md="4" class="pb-0" v-if = "Tutor2.country && Tutor2.country === 'Philippines'">
						<v-select @change="formChanges"v-model = "Tutor2.team" :items="teams" label="Team" outlined></v-select>
					</v-col>





				</v-row>


				<v-row class="headline">
					Academies
				</v-row>

				<v-row class="mb-5">
					<v-col cols="12" sm="12" md="6" class="pb-0">
						<v-card class="px-3 pb-5" >
							<v-row align="center" no-gutters class="academy mb-3" >
								Select All
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges" value></v-checkbox>

							</v-row>

							<v-card flat class="overflow-y-auto" max-height="300px">
							<v-row align="center" no-gutters class="academy">
								Alton Study
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges" value="Alton Study" v-model = "academies[0]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								Anytalk
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="Anytalk" v-model = "academies[1]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								Bigcat
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="Bigcat" v-model = "academies[2]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								SKN
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="SKN"  v-model = "academies[3]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								Daily Speaking
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="	Daily Speaking"  v-model = "academies[4]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								ECK Edu
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="ECK Edu"  v-model = "academies[5]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								Edunuri
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="Edunuri"  v-model = "academies[6]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								Engforu
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="Engforu"  v-model = "academies[7]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								EnglishTOK
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="EnglishTOK"  v-model = "academies[8]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								EverydayCN
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="EverydayCN"  v-model = "academies[9]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								Flocampus
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="Flocampus"  v-model = "academies[10]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								Future
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="Future"  v-model = "academies[11]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								G Talking
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="G Talking"  v-model = "academies[12]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								GG Youth
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="GG Youth"  v-model = "academies[13]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								Grace Talk
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="Grace Talk"  v-model = "academies[14]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								Himsolutek
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="Himsolutek"  v-model = "academies[15]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								Injae
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="Injae"  v-model = "academies[16]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								JKOLS
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="JKOLS"  v-model = "academies[17]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								JoongAng
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="JoongAng"  v-model = "academies[18]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								JoongAng China
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="JoongAng China"  v-model = "academies[19]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								JTalk
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="JTalk"  v-model = "academies[20]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								Kakyo Edu
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="Kakyo Edu"  v-model = "academies[21]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								Kingdom Edu
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="Kingdom Edu"  v-model = "academies[22]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								Kisan
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="Kisan"  v-model = "academies[23]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								LangTalk
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="LangTalk"  v-model = "academies[24]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								LG Academy
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="LG Academy"  v-model = "academies[25]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								Making Speaker
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="Making Speaker"  v-model = "academies[26]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								Mangolang
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="Mangolang"  v-model = "academies[27]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								Megatalking
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="Megatalking"  v-model = "academies[28]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								MGEnglish
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="MGEnglish"  v-model = "academies[29]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								Mirae
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="Mirae"  v-model = "academies[30]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								MK Edu
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="MK Edu"  v-model = "academies[31]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								Mot English
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="Mot English"  v-model = "academies[32]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								Narae
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="Narae"  v-model = "academies[33]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								Phonetalk
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="Phonetalk"  v-model = "academies[34]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								SayOn
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="SayOn"  v-model = "academies[35]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								SGS
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="SGS"  v-model = "academies[36]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								SKN(Kwak)
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="SKN(Kwak)"  v-model = "academies[37]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								Speaking Mate
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="Speaking Mate"  v-model = "academies[38]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								Talking Run
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="Talking Run"  v-model = "academies[39]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								TeacherWel
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="TeacherWel"  v-model = "academies[40]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								Topsphone
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="Topsphone"  v-model = "academies[41]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								Up Talking Club
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="Up Talking Club"  v-model = "academies[42]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								Wants
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="Wants"  v-model = "academies[43]"></v-checkbox>
							</v-row>
							<v-row align="center" no-gutters class="academy">
								Watjjang
								<v-spacer></v-spacer>
								<v-checkbox @change="formChanges"value="Watjjang"  v-model = "academies[44]"></v-checkbox>
							</v-row>
						</v-card>
						</v-card>
					</v-col>
				</v-row>

				<v-row class="headline">
					Account
				</v-row>

				<v-row>
					<v-col cols="12" sm="12" md="4" class="pb-0">
						<v-text-field @input="formChanges"class="pb-0" label="ID" v-model="Tutor2.id" placeholder="ID" outlined></v-text-field>
					</v-col>
					<v-col cols="12" sm="12" md="4" class="pb-0">
						<v-text-field @input="formChanges"class="pb-0" label="Password" v-model = "Tutor2.pw" placeholder="Password" outlined></v-text-field>
					</v-col>
					<v-col cols="12" sm="12" md="4" class="pb-0">
						<v-text-field @input="formChanges"class="pb-0" label="Confirm password" v-model = "Tutor2.confirm_password" placeholder="Confirm password" outlined></v-text-field>
					</v-col>
				</v-row>

				<v-row>
					<v-spacer></v-spacer>
					<div class="my-2">
						<v-btn color="primary" :disabled = "!verify" @click = "activateAccount">Activate Account</v-btn>
					</div>
				</v-row>




			</v-col>

		</v-row>
	</v-row>

</v-app>
</template>

<script>
export default {
	data: vm => ({
		countries: ['Philippines', 'United States', 'China', 'Japan'],
		teams: ['Amber', 'Diamond', 'Emerald', 'Onyx'],
		start_am: ['5:00', '6:00', '7:00'],
		end_am: ['10:00', '11:00', '12:00', '13:00', '14:00', '15:00'],
		start_pm: ['15:00', '16:00', '17:00', '18:00', '19:00', '20:00'],
		end_pm: ['18:00', '19:00', '20:00', '21:00', '22:00', '23:00', '24:00'],
		affiliation: ['UEducation', 'UTIS', 'GMK(US)'],
		places: ['Home-based ', 'Office-based'],
		languages: ['English', 'Chinese', 'Japanese'],
		date: new Date().toISOString().substr(0, 10),
		dateFormatted: vm.formatDate(new Date().toISOString().substr(0, 10)),
		menu1: false,
		menu2: false,

		Tutor2: [],
		academies: [],
		classType: [],
		verify: false
	}),

	computed: {
		computedDateFormatted() {
			return this.formatDate(this.date)
		},
	},

	watch: {
		date(val) {
			this.dateFormatted = this.formatDate(this.date)
		},

		Tutor2:{
			 immediate: true,
			handler(oldval, newval){


		console.log(oldval, 'adsada')
				console.log(newval, 'ss')
				console.log(this.classType, 'type')
				console.log(this.academies, 'academies')




		},
		deep: true

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

		formChanges(){
			console.log(this.classType, 'type')
			console.log(this.academies.filter(obj => obj).length)
			this.verify = false
			if(this.Tutor2.am || this.Tutor2.pm){

			if(  this.Tutor2.workplace && this.Tutor2.start_am && this.Tutor2.start_pm && this.Tutor2.end_am && this.Tutor2.end_pm && this.Tutor2.affiliation && this.Tutor2.language && this.classType.filter(obj => obj).length > 0 && this.academies.filter(obj => obj).length > 0 && this.Tutor2.id && this.Tutor2.pw && this.Tutor2.confirm_password ===  this.Tutor2.pw && this.Tutor2.country ){


					this.verify = true


			}
			else{

					this.verify = false
			}

}

else{

		this.verify = false
}

		},

		activateAccount(){

			this.Tutor2.starting_date = this.computedDateFormatted
			this.Tutor2.academies = this.academies
			this.Tutor2.class_type = this.classType





if(this.$store.getters.getTutor){

this.$store.dispatch('addTutor', {Tutor: this.$store.getters.getTutor, Tutor2: this.Tutor2})


}


		}
	},
}
</script>


<style lang="css">

  .text{
     vertical-align: middle;
      line-height: 14px;
      height:75px;
  }

  .language, .type, .academy{
    height:40px;
  }

  .schedule{

  }



</style>
