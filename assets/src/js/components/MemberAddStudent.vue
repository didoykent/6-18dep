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

				<v-row class="headline">
					Account Information
				</v-row>

				<v-row class="pb-0">
					<v-col cols="12" sm="6" md="3" class="pb-0">
						<v-text-field class="pb-0" label="Name" placeholder="Name" outlined></v-text-field>
					</v-col>
					<v-col cols="12" sm="6" md="3" class="pb-0">
						<v-text-field class="pb-0" label="Phone Number" placeholder="Phone Number" outlined></v-text-field>
					</v-col>
					<v-col cols="12" sm="6" md="3" class="pb-0">
						<v-text-field class="pb-0" label="ID" placeholder="ID" outlined></v-text-field>
					</v-col>
					<v-col cols="12" sm="6" md="3" class="pb-0">
						<v-text-field class="pb-0" label="Password" type="password" outlined></v-text-field>
					</v-col>
				</v-row>

				<v-row class="headline">
					Class Information
				</v-row>

				<v-row class="pb-0">
					<v-col cols="12" sm="6" md="3" class="pb-0">
				 		<v-checkbox v-model="success"  label="Level Test"></v-checkbox>
					</v-col>
						<v-col  sm="6" md="5" class="pb-0">
	  					<v-menu v-model="menu" :close-on-content-click="false" transition="scale-transition" offset-y full-width max-width="290px" min-width="290px">
	  						<template v-slot:activator="{ on }">
	  							<v-text-field outlined v-model="computedDateFormatted" label="Schedule" placeholder="MM/DD/YYYY format" v-on="on"></v-text-field>
	  						</template>
	  						<v-date-picker v-model="date" no-title @input="menu = false"></v-date-picker>
	  					</v-menu>
					</v-col>
				 </v-row>

				 <v-row class="title font-weight-regular">
 					Regular Class
 				</v-row>

					<v-row class="pb-0">
						<v-col cols="12" sm="12" md="4" class="pb-0">
							<v-select :items="academies" label="Academy" outlined></v-select>
						</v-col>
						<v-col cols="12" sm="12" md="4" class="pb-0">
							<v-select :items="levels" label="Level" outlined></v-select>
						</v-col>
					</v-row>

					<v-row class="pb-0">
						<v-col cols="12" sm="12" md="2" class="pb-0">
							<v-select :items="types" label="Class Type" @change="onChange($event)" v-model="type" outlined></v-select>
						</v-col>
						<v-col cols="12" sm="12" md="2" class="pb-0">
							<v-select :items="frequencies" label="Frequency" outlined  v-model="frequency"></v-select>
						</v-col>
						<v-col cols="12" sm="12" md="3" class="pb-0">
							<v-select :items="durations" label="Duration" v-model="duration"  outlined></v-select>
						</v-col>
						<v-col cols="12" sm="12" md="3" class="pb-0">
							<v-select :items="periods" label="Period" v-model="period" outlined></v-select>
						</v-col>
					</v-row>

					<v-row>
						<v-col  sm="6" md="3" class="pb-0">
	  					<v-menu v-model="menu2" :close-on-content-click="false" transition="scale-transition" offset-y full-width max-width="290px" min-width="290px">
	  						<template v-slot:activator="{ on }">
	  							<v-text-field outlined v-model="computedDateFormatted2" label="Date	" placeholder="MM/DD/YYYY format" v-on="on"></v-text-field>
	  						</template>
	  						<v-date-picker v-model="date2" no-title @input="menu2 = false"></v-date-picker>
	  					</v-menu>
					</v-col>
					<v-col cols="12" sm="12" md="2" class="pb-0">
						<v-select :items="hours" label="Hour" outlined></v-select>
					</v-col>
					<v-col cols="12" sm="12" md="2" class="pb-0">
						<v-select :items="minutes" label="Minutes" outlined></v-select>
					</v-col>
					<v-col cols="12" sm="12" md="3" class="pb-0">
						<v-select :items="instructors" label="Instructor" outlined></v-select>
					</v-col>
					</v-row>

					<v-row class="headline">
						Reference
					</v-row>


					<v-row class="pb-0">
						<v-col cols="12" sm="6" md="6" class="pb-0">
							<v-text-field class="pb-0" label="Book Search" placeholder="Book Search" outlined></v-text-field>
						</v-col>
						<v-spacer></v-spacer>
						<v-col cols="12" sm="6" md="3" class="pb-0">
							<v-text-field class="pb-0" label="Coupon" placeholder="Coupon Code" outlined></v-text-field>
						</v-col>
					</v-row>

					<v-row class="pb-0 mr-1" justify="end" align="center">
							<v-spacer></v-spacer>
							 <span class="mr-5 headline font-weight-black">{{krw}}</span></span>
							 <span class="mr-10 headline font-weight-black">{{price}}</span></span>
							<v-btn class="ml-2" color="primary">UPay</v-btn>
					</v-row>


			</v-col>

		</v-row>
	</v-row>

</v-app>
</template>

<script>

import vue from 'vue'

export default {
	data: vm => ({

		price: "",
		menu: "",
		start_am: ['5:00', '6:00', '7:00'],
		end_am: ['10:00', '11:00', '12:00', '13:00', '14:00', '15:00'],
		start_pm: ['15:00', '16:00', '17:00', '18:00', '19:00', '20:00'],
		end_pm: ['18:00', '19:00', '20:00', '21:00', '22:00', '23:00', '24:00'],
		affiliation: ['UEducation', 'UTIS', 'GMK(US)'],
		languages: ['English', 'Chinese', 'Japanese'],

		krw: "",
		type: "",
		frequency: "",
		duration: "",
		period: "",

		academies: ['Alton Study', 'Anytalk', 'Bigcat', 'Daily Speaking', 'ECK Edu', 'Edunuri', 'Engforu', 'EnglishTOK', 'EverydayCN', 'Flocampus',
		'Future', 'G Talking', 'GG Youth', 'Grace Talk', 'Himsolutek', 'Injae', 'JKOLS', 'JoongAng', 'JoongAng China', 'JTalk',
		 'Kakyo Edu', 'Kingdom Edu', 'Kisan', 'LangTalk', 'LG Academy', 'Making Speaker',
		 'Mangolang', 'Megatalking', 'MGEnglish', 'Mirae', 'MK Edu', 'Mot English',
		'Narae', 'Phonetalk', 'SayOn', 'SGS', 'SKN(Kwak)', 'Speaking Mate', 'Talking Run',
		'TeacherWel', 'Topsphone', 'Up Talking Club', 'Wants', 'Watjjang'],

		levels: ['Low Beginner', 'Beginner', 'High Beginner', 'Low Intermediate',
		'Intermediate', 'High Intermediate',
		'Pre Advance', 'Advance', 'Post Advance'],

		types: ['Phone', 'Video'],
		frequencies: ['2x a week', '3x a week', '5x a week'],
		durations: [],
		periods: [],

		phone_durations: ['10 minutes', '20 minutes'],
		video_durations: ['20 minutes', '30 minutes', '40 minutes', '50 minutes'],

		phone_periods: ['1 month', '3 months', '6 months + 1'],
		video_periods: ['1 month', '3 months', '6 months'],

		hours: ['5:00', '6:00', '7:00', '8:00', '9:00', '10:00', '11:00', '12:00', '13:00', '14:00', '15:00', '16:00', '17:00', '18:00', '19:00', '20:00', '21:00', '22:00', '23:00'],
		minutes: ['10', '20', '30', '40', '50',],

		date: new Date().toISOString().substr(0, 10),
		date2: new Date().toISOString().substr(0, 10),
		dateFormatted: vm.formatDate(new Date().toISOString().substr(0, 10)),
		dateFormatted2: vm.formatDate2(new Date().toISOString().substr(0, 10)),
		menu1: false,
		menu2: false,
	}),

	computed: {
		computedDateFormatted() {
			return this.formatDate(this.date)
		},

		computedDateFormatted2() {
			return this.formatDate(this.date2)
		},
	},

	watch: {
		date(val) {
			this.dateFormatted = this.formatDate(this.date)
		},

		date2(val2) {
			this.dateFormatted2 = this.formatDate2(this.date2)
		},

		type: function(val){
				this.checkPrice()
		},
		frequency: function(val){
				this.checkPrice()
		},
		duration: function(val){
				this.checkPrice()
		},
		period: function(val){
				this.checkPrice()
		},



	},

	methods: {
		formatDate(date) {
			if (!date) return null

			const [year, month, day] = date.split('-')
			return `${month}/${day}/${year}`
		},

		formatDate2(date2) {
			if (!date2) return null

			const [year, month, day] = date2.split('-')
			return `${month}/${day}/${year}`
		},

		parseDate(date) {
			if (!date) return null

			const [month, day, year] = date.split('/')
			return `${year}-${month.padStart(2, '0')}-${day.padStart(2, '0')}`
		},

		parseDate2(date2) {
			if (!date2) return null

			const [month, day, year] = date2.split('/')
			return `${year}-${month.padStart(2, '0')}-${day.padStart(2, '0')}`
		},

		onChange(event) {
					 console.log(event)
					 if(event == "Phone"){

						 vue.set(this.$data, 'durations', this.$data.phone_durations)
						 vue.set(this.$data, 'periods', this.$data.phone_periods)

					 }else if(event == "Video"){

						  vue.set(this.$data, 'durations',this.$data.video_durations)
							vue.set(this.$data, 'periods', this.$data.video_periods)

					 }
			 },

			checkPrice(){
				if(this.type !== "" && this.frequency !== "" && this.duration !== "" && this.period !== ""){
					this.krw = "KRW"
				}
				if(this.type === "Phone" && this.frequency === "5x a week" && this.duration === "10 minutes" && this.period === "1 month"){
					this.price = "100,000"
				}
				if(this.type === "Phone" && this.frequency === "5x a week" && this.duration === "10 minutes" && this.period === "3 months"){
					this.price = "290,000"
				}
				if(this.type === "Phone" && this.frequency === "5x a week" && this.duration === "10 minutes" && this.period === "6 months + 1"){
					this.price = "600,000"
				}
				if(this.type === "Phone" && this.frequency === "5x a week" && this.duration === "20 minutes" && this.period === "1 month"){
					this.price = "190,000"
				}
				if(this.type === "Phone" && this.frequency === "5x a week" && this.duration === "20 minutes" && this.period === "3 months"){
					this.price = "560,000"
				}
				if(this.type === "Phone" && this.frequency === "3x a week" && this.duration === "10 minutes" && this.period === "6 months + 1"){
					this.price = "70,000"
				}
				if(this.type === "Phone" && this.frequency === "3x a week" && this.duration === "10 minutes" && this.period === "3 months"){
					this.price = "200,000"
				}
				if(this.type === "Phone" && this.frequency === "3x a week" && this.duration === "10 minutes" && this.period === "6 months + 1"){
					this.price = "420,000"
				}
				if(this.type === "Phone" && this.frequency === "3x a week" && this.duration === "20 minutes" && this.period === "1 month"){
					this.price = "130,000"
				}
				if(this.type === "Phone" && this.frequency === "3x a week" && this.duration === "20 minutes" && this.period === "3 months"){
					this.price = "380,000"
				}
				if(this.type === "Phone" && this.frequency === "3x a week" && this.duration === "20 minutes" && this.period === "6 months + 1"){
					this.price = "780,000"
				}
				if(this.type === "Phone" && this.frequency === "2x a week" && this.duration === "10 minutes" && this.period === "1 month"){
					this.price = "45,000 "
				}
				if(this.type === "Phone" && this.frequency === "2x a week" && this.duration === "10 minutes" && this.period === "3 months"){
					this.price = "125,000"
				}
				if(this.type === "Phone" && this.frequency === "2x a week" && this.duration === "10 minutes" && this.period === "6 months + 1"){
					this.price = "270,000"
				}
				if(this.type === "Phone" && this.frequency === "2x a week" && this.duration === "20 minutes" && this.period === "1 month"){
					this.price = "80,000"
				}
				if(this.type === "Phone" && this.frequency === "2x a week" && this.duration === "20 minutes" && this.period === "3 months"){
					this.price = "230,000"
				}
				if(this.type === "Phone" && this.frequency === "2x a week" && this.duration === "20 minutes" && this.period === "6 months + 1"){
					this.price = "480,000"
				}
				if(this.type === "Video" && this.frequency === "2x a week" && this.duration === "20 minutes" && this.period === "1 month"){
					this.price = "88,000"
				}
				if(this.type === "Video" && this.frequency === "2x a week" && this.duration === "20 minutes" && this.period === "3 months"){
					this.price = "250,000"
				}
				if(this.type === "Video" && this.frequency === "2x a week" && this.duration === "20 minutes" && this.period === "6 months"){
					this.price = "475,000"
				}
				if(this.type === "Video" && this.frequency === "3x a week" && this.duration === "20 minutes" && this.period === "1 month"){
					this.price = "118,000"
				}
				if(this.type === "Video" && this.frequency === "3x a week" && this.duration === "20 minutes" && this.period === "3 months"){
					this.price = "337,000"
				}
				if(this.type === "Video" && this.frequency === "3x a week" && this.duration === "20 minutes" && this.period === "6 months"){
					this.price = "637,000"
				}
				if(this.type === "Video" && this.frequency === "5x a week" && this.duration === "20 minutes" && this.period === "1 month"){
					this.price = "148,000"
				}
				if(this.type === "Video" && this.frequency === "5x a week" && this.duration === "20 minutes" && this.period === "3 months"){
					this.price = "442,000"
				}
				if(this.type === "Video" && this.frequency === "5x a week" && this.duration === "20 minutes" && this.period === "6 months"){
					this.price = "779,000"
				}
				if(this.type === "Video" && this.frequency === "2x a week" && this.duration === "30 minutes" && this.period === "1 month"){
					this.price = "120,000"
				}
				if(this.type === "Video" && this.frequency === "2x a week" && this.duration === "30 minutes" && this.period === "3 months"){
					this.price = "324,000"
				}
				if(this.type === "Video" && this.frequency === "2x a week" && this.duration === "30 minutes" && this.period === "6 months"){
					this.price = "628,000"
				}
				if(this.type === "Video" && this.frequency === "3x a week" && this.duration === "30 minutes" && this.period === "1 month"){
					this.price = "162,000"
				}
				if(this.type === "Video" && this.frequency === "3x a week" && this.duration === "30 minutes" && this.period === "3 months"){
					this.price = "462,000"
				}
				if(this.type === "Video" && this.frequency === "3x a week" && this.duration === "30 minutes" && this.period === "6 months"){
					this.price = "875,000"
				}
				if(this.type === "Video" && this.frequency === "5x a week" && this.duration === "30 minutes" && this.period === "1 month"){
					this.price = "210,000"
				}
				if(this.type === "Video" && this.frequency === "5x a week" && this.duration === "30 minutes" && this.period === "3 months"){
					this.price = "599,000"
				}
				if(this.type === "Video" && this.frequency === "5x a week" && this.duration === "30 minutes" && this.period === "6 months"){
					this.price = "1,134,000"
				}
				if(this.type === "Video" && this.frequency === "2x a week" && this.duration === "40 minutes" && this.period === "1 month"){
					this.price = "114,000"
				}
				if(this.type === "Video" && this.frequency === "2x a week" && this.duration === "40 minutes" && this.period === "3 months"){
					this.price = "410,000"
				}
				if(this.type === "Video" && this.frequency === "2x a week" && this.duration === "40 minutes" && this.period === "6 months"){
					this.price = "778,000"
				}
				if(this.type === "Video" && this.frequency === "3x a week" && this.duration === "40 minutes" && this.period === "1 month"){
					this.price = "192,000"
				}
				if(this.type === "Video" && this.frequency === "3x a week" && this.duration === "40 minutes" && this.period === "3 months"){
					this.price = "547,000"
				}
				if(this.type === "Video" && this.frequency === "3x a week" && this.duration === "40 minutes" && this.period === "6 months"){
					this.price = "1.037,000"
				}
				if(this.type === "Video" && this.frequency === "5x a week" && this.duration === "40 minutes" && this.period === "1 month"){
					this.price = "240,000"
				}
				if(this.type === "Video" && this.frequency === "5x a week" && this.duration === "40 minutes" && this.period === "3 months"){
					this.price = "684,000"
				}
				if(this.type === "Video" && this.frequency === "5x a week" && this.duration === "40 minutes" && this.period === "6 months"){
					this.price = "1.296,000"
				}
				if(this.type === "Video" && this.frequency === "2x a week" && this.duration === "50 minutes" && this.period === "1 month"){
					this.price = "162,000"
				}
				if(this.type === "Video" && this.frequency === "2x a week" && this.duration === "50 minutes" && this.period === "3 months"){
					this.price = "461,000"
				}
				if(this.type === "Video" && this.frequency === "2x a week" && this.duration === "50 minutes" && this.period === "6 months"){
					this.price = "874,000"
				}
				if(this.type === "Video" && this.frequency === "3x a week" && this.duration === "50 minutes" && this.period === "1 month"){
						this.price = "218,000"
				}
				if(this.type === "Video" && this.frequency === "3x a week" && this.duration === "50 minutes" && this.period === "3 months"){
					this.price = "621,000"
				}
				if(this.type === "Video" && this.frequency === "3x a week" && this.duration === "50 minutes" && this.period === "6 months"){
					this.price = "1,177,000"
				}
				if(this.type === "Video" && this.frequency === "5x a week" && this.duration === "50 minutes" && this.period === "1 month"){
					this.price = "273,000"
				}
				if(this.type === "Video" && this.frequency === "5x a week" && this.duration === "50 minutes" && this.period === "3 months"){
					this.price = "777,000"
				}
				if(this.type === "Video" && this.frequency === "5x a week" && this.duration === "50 minutes" && this.period === "6 months"){
					this.price = "1,470,000"
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
