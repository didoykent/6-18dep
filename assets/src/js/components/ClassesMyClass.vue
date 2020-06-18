<template>
<v-app>

	<v-row>
		<v-row class="mx-5 my-5" align="stretch">
			<v-col cols="3">

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

</script>
