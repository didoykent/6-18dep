<template>
	<v-container>
		<v-card flat>
			<v-row>
				<v-col cols="12" md="12">
					<v-card flat>
						<v-card-title class="headline">
							<div class="d-flex justify-content-center align-items-center mr-2" style="height:50px;width:50px;
							background-color:#E91E63;">
							<v-icon color="white" x-large>account_balance</v-icon>
						</div>
						Academies
					</v-card-title>
				</v-card>
			</v-col>
		</v-row>
		<v-row class="mt-3 ml-2">
			<v-col cols="12" sm="4" md="2" align="center" class="pb-0">
				<v-text-field class="pb-0" label="Search" placeholder="Search Academy" v-model="search" outlined></v-text-field>
			</v-col>
			<v-col cols="12" sm="4" md="5" align="center" class="pb-0">
				<v-row>
					<v-col cols="12" sm="4" md="2" justify="center" class=" nav px-0">
						<v-btn block text :style="buttonColor1" @click="navClick($event)">Information</v-btn>
					</v-col>
					<v-divider vertical></v-divider>
					<v-col cols="12" sm="4" md="2" align="center" justify="center" class="nav px-0">
						<v-btn block text :style="buttonColor2" @click="navClick($event)">Students</v-btn>
					</v-col>
					<v-divider vertical></v-divider>
					<v-col cols="12" sm="4" md="2" align="center" justify="center" class="nav px-0">
						<v-btn block text :style="buttonColor3" @click="navClick($event)">Price List</v-btn>
					</v-col>
					<v-divider vertical></v-divider>
				</v-row>
			</v-col>
		</v-row>

		<v-row class="ml-2">
			<v-col cols="12" sm="4" md="2" align="center" class="pt-0">
				<v-container>

					<v-row class="pr-4 mb-4">
						<v-btn block color="#E91E63" class="white--text " @click="addAcademyDialog = true">Add New</v-btn>
					</v-row>
					<v-row>
						<v-card class="overflow-y-auto" max-height="500px">
							<v-list>
								<template>
									<v-list-item-group color="primary">
										<v-list-item v-for="(academy, index) in filteredList" :key="academy">
											<v-list-item-content>
												<v-list-item-title style="color:#E91E63" @click="selectAcademy({academy})">{{academy.name}}</v-list-item-title>
											</v-list-item-content>
										</v-list-item>
									</v-list-item-group>
								</template>
							</v-list>
						</v-card>
					</v-row>

				</v-container>
			</v-col>
			<v-col cols="12" md="10" class="pt-0" max-height="100">
				<v-card v-if="currentComponent === 'Information'" max-height="500" class="overflow-y-auto pa-2">
					Information Layout
				</v-card>
				<v-card v-if="currentComponent === 'Students'" max-height="500" class="overflow-y-auto pa-2">
					Student Design
				</v-card>
				<v-card v-if="currentComponent === 'PriceTable'" max-height="500" class="overflow-y-auto pa-2">
					<PriceTable></PriceTable>
				</v-card>
			</v-col>
		</v-row>
	</v-col>
</v-row>

	<v-dialog v-model="addAcademyDialog" max-width="1100">
		<v-card>
				<v-card flat>
					<v-card-title class="headline">
						<div class="d-flex justify-content-center align-items-center mr-2" style="height:50px;width:50px;
						background-color:#E91E63;">
						<v-icon color="white" x-large>account_balance</v-icon>
					</div>
					Add New Academy
				</v-card-title>
				<v-container class="pa-5">
					<v-row>
						<v-col cols="12" md="6">
							<v-text-field  v-model = "Academy.name"label="Academy Name"></v-text-field>
						</v-col>
						<v-col cols="12" md="6">
							<v-text-field  v-model = "Academy.website"label="Website"></v-text-field>
						</v-col>
					</v-row>
					<v-row>
						<v-col cols="12">
							<v-textarea v-model = "Academy.description"filled label="Description"></v-textarea>
						</v-col>
					</v-row>
					<v-row>
						<v-col cols="12">
							<v-textarea v-model = "Academy.special_instruction"filled label="Special Instruction"></v-textarea>
						</v-col>
					</v-row>
					<v-row>
						<v-col cols="12" md="6">
							<v-text-field v-model = "Academy.cs_number"label="Customer Service Number"></v-text-field>
						</v-col>
						<v-col cols="12" md="6">
							<v-text-field  v-model = "Academy.calling_prefix" label="Calling Prefix"></v-text-field>
						</v-col>
					</v-row>
					<v-row class="d-flex justify-content-end">
						<v-btn text @click="addAcademyDialog = false">Cancel</v-btn>
						<v-btn class="white--text ml-2" color="#E91E63" @click = "addAcademy()">Save</v-btn>
					</v-row>
				</v-container>

			</v-card>

		</v-card>
	</v-dialog>

</v-card>
</v-container>
</v-row>

</v-container>
</template>

<script>
import axios from 'axios'
import Vue from 'vue'
import PriceTable from './PriceTable'

export default {

	components: {
		PriceTable
	},

	data() {
		return {


			Academy: [],

			buttonColor1: '',
			buttonColor2: '',
			buttonColor3: '',
			currentComponent: 'Information',
			search: '',
			academyList: [],
		src: '',
		addAcademyDialog: false,

	}
},

computed: {
	filteredList() {
		if (this.search) {
			return this.academyList.filter((academy) => academy.toLowerCase().indexOf(this.search.toLowerCase()) > -1);
		} else {
			return this.academyList;
		}
	}
},

mounted() {
	if (this.currentComponent == 'Information') {
		this.buttonColor1 = 'background-color:#E91E63;color:white'
		this.buttonColor2 = ''
		this.buttonColor3 = ''
	}

this.getAcademies()


},

methods: {

	navClick(selected) {
		console.log(selected.target.innerText)
		if (selected.target.innerText == 'INFORMATION') {
			this.currentComponent = 'Information'
			this.buttonColor1 = 'background-color:#E91E63;color:white'
			this.buttonColor2 = ''
			this.buttonColor3 = ''
		} else if (selected.target.innerText == 'STUDENTS') {
			this.currentComponent = 'Students'
			this.buttonColor1 = ''
			this.buttonColor2 = 'background-color:#E91E63;color:white'
			this.buttonColor3 = ''
		} else if (selected.target.innerText == 'PRICE LIST') {
			this.currentComponent = 'PriceTable'
			this.buttonColor1 = ''
			this.buttonColor2 = ''
			this.buttonColor3 = 'background-color:#E91E63;color:white'
		}
	},

	addAcademy(){

console.log(this.Academy)

		if(this.Academy){

				const form = new FormData()

				form.append('name', this.Academy.name)
				form.append('website', this.Academy.website)
				form.append('description', this.Academy.description)
				form.append('special_instruction', this.Academy.special_instruction)
				form.append('cs_number', this.Academy.cs_number)
				form.append('calling_prefix', this.Academy.calling_prefix)

				axios.post('Academy/addAcademy', form).then(res => {

				if(res.data.error === false){

					location.reload()
				}
				})


		}
	},

	async getAcademies(){


		await axios.get('Academy/showAll').then(res => {

			if(res.data.academy){

				this.$set(this.$data, 'academyList', res.data.academy)
			}
		})
	}

}

}
</script>

<style scoped lang="css">

.v-messages .theme--light .messages__wrapper{
	height: 0px;
}

.link{
	text-decoration: none;
}

.router-link{
	background:blue;
}

.nav{
	max-width: 200px;
}
</style>
